// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	dampeningDeltaReuse     = 10 * time.Second
	dampeningDeltaT         = 5 * time.Second
	dampeningDefaultPenalty = 1000
	dampeningAttrPenalty    = 500
)

type dampeningConfig struct {
	reuseLimit      int
	suppressValue   int
	halfLife        time.Duration
	maxSuppressTime time.Duration
	ceiling         int
	decayArray      []float64
}

func newDampeningConfig(c oc.DampeningConfig) *dampeningConfig {
	if c.HalfLife == 0 {
		c.HalfLife = oc.DEFAULT_DAMPENING_HALF_LIFE
	}
	if c.ReuseThreshold == 0 {
		c.ReuseThreshold = oc.DEFAULT_DAMPENING_REUSE_THRESHOLD
	}
	if c.SuppressThreshold == 0 {
		c.SuppressThreshold = oc.DEFAULT_DAMPENING_SUPPRESS_THRESHOLD
	}
	if c.MaxSuppressTime == 0 {
		c.MaxSuppressTime = c.HalfLife * oc.DEFAULT_DAMPENING_MAX_SUPPRESS_MULT
	}
	halfLife := time.Duration(c.HalfLife) * time.Minute
	maxSuppressTime := time.Duration(c.MaxSuppressTime) * time.Minute
	d := &dampeningConfig{
		reuseLimit:      int(c.ReuseThreshold),
		suppressValue:   int(c.SuppressThreshold),
		halfLife:        halfLife,
		maxSuppressTime: maxSuppressTime,
	}
	ceiling := float64(d.reuseLimit) * math.Pow(2, float64(d.maxSuppressTime)/float64(d.halfLife))
	maxInt := int(^uint(0) >> 1)
	if ceiling > float64(maxInt) {
		d.ceiling = maxInt
	} else {
		d.ceiling = int(ceiling)
	}
	size := int(math.Ceil(float64(d.maxSuppressTime) / float64(dampeningDeltaT)))
	if size < 2 {
		size = 2
	}
	d.decayArray = make([]float64, size)
	d.decayArray[0] = 1
	d.decayArray[1] = math.Exp((1 / (float64(d.halfLife) / float64(dampeningDeltaT))) * math.Log(0.5))
	for i := 2; i < len(d.decayArray); i++ {
		d.decayArray[i] = d.decayArray[i-1] * d.decayArray[1]
	}
	return d
}

func (d *dampeningConfig) decay(td time.Duration, penalty int) int {
	if d == nil || penalty <= 0 {
		return 0
	}
	i := int(td / dampeningDeltaT)
	if i == 0 {
		return penalty
	}
	if i >= len(d.decayArray) {
		return 0
	}
	return int(float64(penalty) * d.decayArray[i])
}

type dampeningRecordType uint8

const (
	dampeningRecordUpdate dampeningRecordType = iota
	dampeningRecordWithdraw
)

type dampeningKey struct {
	peer   netip.Addr
	family bgp.Family
	prefix string
	pathID uint32
}

type dampeningInfo struct {
	penalty      int
	flap         int
	startTime    time.Time
	updatedTime  time.Time
	suppressTime time.Time
	suppressed   bool
	lastRecord   dampeningRecordType
	activePath   *table.Path
	pendingPath  *table.Path
	config       *dampeningConfig
	configValue  oc.DampeningConfig
}

type dampeningManager struct {
	mu    sync.Mutex
	infos map[dampeningKey]*dampeningInfo
	now   func() time.Time
}

func newDampeningManager() *dampeningManager {
	return &dampeningManager{
		infos: make(map[dampeningKey]*dampeningInfo),
		now:   time.Now,
	}
}

func dampeningPathKey(path *table.Path) dampeningKey {
	source := path.GetSource()
	return dampeningKey{
		peer:   source.Address,
		family: path.GetFamily(),
		prefix: path.GetNlri().String(),
		pathID: path.RemoteID(),
	}
}

func dampeningFamilySupported(f bgp.Family) bool {
	switch f {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_MC, bgp.RF_IPv6_MC:
		return true
	default:
		return false
	}
}

func findAfiSafiDampening(afs []oc.AfiSafi, family bgp.Family) (oc.DampeningConfig, bool) {
	name := oc.AfiSafiType(family.String())
	for _, af := range afs {
		if af.Config.AfiSafiName == name && af.Dampening.Config.Enabled {
			return af.Dampening.Config, true
		}
	}
	return oc.DampeningConfig{}, false
}

func (s *BgpServer) dampeningConfigFor(peer *peer, path *table.Path) (oc.DampeningConfig, bool) {
	if peer == nil || path == nil || path.IsEOR() || !dampeningFamilySupported(path.GetFamily()) {
		return oc.DampeningConfig{}, false
	}
	conf := peer.fsm.pConf.ReadOnly()
	if conf.State.PeerType != oc.PEER_TYPE_EXTERNAL {
		return oc.DampeningConfig{}, false
	}
	if conf.Config.Vrf != "" {
		return oc.DampeningConfig{}, false
	}
	if c, ok := findAfiSafiDampening(conf.AfiSafis, path.GetFamily()); ok {
		return c, true
	}
	if conf.Dampening.Config.Enabled {
		return conf.Dampening.Config, true
	}
	if conf.Config.RouteFlapDamping {
		return oc.DampeningConfig{
			Enabled:           true,
			HalfLife:          oc.DEFAULT_DAMPENING_HALF_LIFE,
			ReuseThreshold:    oc.DEFAULT_DAMPENING_REUSE_THRESHOLD,
			SuppressThreshold: oc.DEFAULT_DAMPENING_SUPPRESS_THRESHOLD,
			MaxSuppressTime:   oc.DEFAULT_DAMPENING_HALF_LIFE * oc.DEFAULT_DAMPENING_MAX_SUPPRESS_MULT,
		}, true
	}
	if pg, ok := s.peerGroupMap[conf.Config.PeerGroup]; ok {
		if c, ok := findAfiSafiDampening(pg.Conf.AfiSafis, path.GetFamily()); ok {
			return c, true
		}
		if pg.Conf.Dampening.Config.Enabled {
			return pg.Conf.Dampening.Config, true
		}
	}
	if c, ok := findAfiSafiDampening(s.bgpConfig.Global.AfiSafis, path.GetFamily()); ok {
		return c, true
	}
	if s.bgpConfig.Global.Dampening.Config.Enabled {
		return s.bgpConfig.Global.Dampening.Config, true
	}
	return oc.DampeningConfig{}, false
}

func (m *dampeningManager) apply(path *table.Path, conf oc.DampeningConfig) []*table.Path {
	if m == nil || path == nil || !conf.Enabled {
		return []*table.Path{path}
	}
	key := dampeningPathKey(path)
	now := m.now()
	cfg := newDampeningConfig(conf)

	m.mu.Lock()
	defer m.mu.Unlock()

	info := m.infos[key]
	if info != nil && info.configValue != conf {
		info.config = cfg
		info.configValue = conf
	}
	if info == nil {
		info = &dampeningInfo{config: cfg, configValue: conf}
		m.infos[key] = info
	}
	if info.config == nil {
		info.config = cfg
		info.configValue = conf
	}

	if path.IsWithdraw {
		return m.withdrawLocked(info, path, false, now)
	}
	return m.updateLocked(info, path, now)
}

func (m *dampeningManager) withdrawLocked(info *dampeningInfo, path *table.Path, attrChange bool, now time.Time) []*table.Path {
	if info.updatedTime.IsZero() {
		info.startTime = now
		info.updatedTime = now
		info.penalty = 0
	}
	info.penalty = info.config.decay(now.Sub(info.updatedTime), info.penalty)
	if attrChange {
		info.penalty += dampeningAttrPenalty
	} else {
		info.penalty += dampeningDefaultPenalty
	}
	if info.penalty > info.config.ceiling {
		info.penalty = info.config.ceiling
	}
	info.flap++
	info.updatedTime = now
	info.lastRecord = dampeningRecordWithdraw
	info.pendingPath = nil
	if !attrChange {
		info.activePath = nil
	}
	if info.suppressed {
		return nil
	}
	if info.penalty >= info.config.suppressValue {
		info.suppressed = true
		info.suppressTime = now
	}
	if attrChange {
		return nil
	}
	return []*table.Path{path}
}

func (m *dampeningManager) updateLocked(info *dampeningInfo, path *table.Path, now time.Time) []*table.Path {
	if info.activePath != nil && !path.Equal(info.activePath) {
		withdraw := info.activePath.Clone(true)
		m.withdrawLocked(info, withdraw, true, now)
		if info.suppressed && info.penalty >= info.config.reuseLimit {
			info.lastRecord = dampeningRecordUpdate
			info.pendingPath = path
			info.activePath = nil
			return []*table.Path{withdraw}
		}
	}

	if info.updatedTime.IsZero() {
		info.activePath = path
		info.lastRecord = dampeningRecordUpdate
		return []*table.Path{path}
	}
	info.penalty = info.config.decay(now.Sub(info.updatedTime), info.penalty)
	info.updatedTime = now
	info.lastRecord = dampeningRecordUpdate

	if info.suppressed {
		if info.penalty < info.config.reuseLimit {
			info.suppressed = false
			info.suppressTime = time.Time{}
			info.pendingPath = nil
			info.activePath = path
			return []*table.Path{path}
		}
		info.pendingPath = path
		info.activePath = nil
		return nil
	}
	if info.penalty >= info.config.suppressValue {
		withdraw := path.Clone(true)
		if info.activePath != nil {
			withdraw = info.activePath.Clone(true)
		}
		info.suppressed = true
		info.suppressTime = now
		info.pendingPath = path
		info.activePath = nil
		return []*table.Path{withdraw}
	}
	info.pendingPath = nil
	info.activePath = path
	if info.penalty <= info.config.reuseLimit/2 {
		info.penalty = 0
		info.flap = 0
	}
	return []*table.Path{path}
}

func (m *dampeningManager) tick() []*table.Path {
	if m == nil {
		return nil
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()

	paths := make([]*table.Path, 0)
	for key, info := range m.infos {
		if info.config == nil || info.updatedTime.IsZero() {
			continue
		}
		info.penalty = info.config.decay(now.Sub(info.updatedTime), info.penalty)
		info.updatedTime = now
		if !info.suppressed {
			if info.penalty <= info.config.reuseLimit/2 && info.activePath == nil {
				delete(m.infos, key)
			}
			continue
		}
		if info.penalty >= info.config.reuseLimit {
			continue
		}
		info.suppressed = false
		info.suppressTime = time.Time{}
		if info.lastRecord == dampeningRecordUpdate && info.pendingPath != nil {
			info.activePath = info.pendingPath
			paths = append(paths, info.pendingPath)
			info.pendingPath = nil
			continue
		}
		if info.penalty <= info.config.reuseLimit/2 {
			delete(m.infos, key)
		}
	}
	return paths
}

func (s *BgpServer) startDampeningTicker() {
	if s.dampening == nil || s.runningCtx == nil {
		return
	}
	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done()
		ticker := time.NewTicker(dampeningDeltaReuse)
		defer ticker.Stop()
		for {
			select {
			case <-s.runningCtx.Done():
				return
			case <-ticker.C:
				s.reuseDampenedPaths()
			}
		}
	}()
}

func (s *BgpServer) reuseDampenedPaths() {
	for _, path := range s.dampening.tick() {
		s.reuseDampenedPath(path)
	}
}

func (s *BgpServer) reuseDampenedPath(path *table.Path) {
	if path == nil {
		return
	}
	source := path.GetSource()
	if source == nil || !source.Address.IsValid() {
		return
	}

	s.shared.mu.RLock()
	peer := s.neighborMap[source.Address]
	s.shared.mu.RUnlock()
	if peer == nil {
		return
	}

	rib := s.globalRib
	if peer.isRouteServerClient() {
		rib = s.rsRib
	}
	bucket := s.shared.propagateBucket(path)
	bucket.Lock()
	defer bucket.Unlock()
	if dsts := rib.Update(path); len(dsts) > 0 {
		s.propagateUpdateToNeighbors(rib, peer, path, dsts, true)
	}
}
