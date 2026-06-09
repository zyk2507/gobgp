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
	dampeningReuseArraySize = 1024
	dampeningReuseListSize  = 256
	dampeningNoReuseIndex   = -1
	dampeningReuseIndexNone = -2
)

type dampeningConfig struct {
	reuseLimit      int
	suppressValue   int
	halfLife        time.Duration
	maxSuppressTime time.Duration
	ceiling         int
	decayArray      []float64
	reuseListSize   int
	reuseIndexSize  int
	scaleFactor     float64
	reuseIndex      []int
}

func normalizeDampeningConfigValue(c oc.DampeningConfig) oc.DampeningConfig {
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
	return c
}

func newDampeningConfig(c oc.DampeningConfig) *dampeningConfig {
	c = normalizeDampeningConfigValue(c)
	halfLife := time.Duration(c.HalfLife) * time.Minute
	maxSuppressTime := time.Duration(c.MaxSuppressTime) * time.Minute
	d := &dampeningConfig{
		reuseLimit:      int(c.ReuseThreshold),
		suppressValue:   int(c.SuppressThreshold),
		halfLife:        halfLife,
		maxSuppressTime: maxSuppressTime,
		reuseIndexSize:  dampeningReuseArraySize,
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

	reuseListSize := int(math.Ceil(float64(d.maxSuppressTime)/float64(dampeningDeltaReuse))) + 1
	if reuseListSize > dampeningReuseListSize || reuseListSize == 0 {
		reuseListSize = dampeningReuseListSize
	}
	if reuseListSize < 1 {
		reuseListSize = 1
	}
	d.reuseListSize = reuseListSize

	reuseMaxRatio := float64(d.ceiling) / float64(d.reuseLimit)
	j := math.Exp(float64(d.maxSuppressTime)/float64(d.halfLife)) * math.Log10(2.0)
	if reuseMaxRatio > j && j != 0 {
		reuseMaxRatio = j
	}
	if reuseMaxRatio <= 1 {
		reuseMaxRatio = 1 + 1/float64(d.reuseIndexSize)
	}
	d.scaleFactor = float64(d.reuseIndexSize) / (reuseMaxRatio - 1)
	d.reuseIndex = make([]int, d.reuseIndexSize)
	for i := range d.reuseIndex {
		d.reuseIndex[i] = int((float64(d.halfLife) / float64(dampeningDeltaReuse)) *
			math.Log10(1.0/(float64(d.reuseLimit)*(1.0+float64(i)/d.scaleFactor))) / math.Log10(0.5))
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

func (d *dampeningConfig) reuseTime(penalty int) time.Duration {
	if d == nil || penalty <= d.reuseLimit || d.reuseLimit <= 0 || len(d.decayArray) < 2 {
		return 0
	}
	ticks := math.Log(float64(d.reuseLimit)/float64(penalty)) / math.Log(d.decayArray[1])
	if ticks <= 0 {
		return 0
	}
	reuseTime := time.Duration(ticks * float64(dampeningDeltaT))
	if reuseTime > d.maxSuppressTime {
		return d.maxSuppressTime
	}
	return reuseTime
}

type dampeningRecordType uint8

const (
	dampeningRecordUpdate dampeningRecordType = iota
	dampeningRecordWithdraw
)

func (r dampeningRecordType) String() string {
	switch r {
	case dampeningRecordUpdate:
		return "update"
	case dampeningRecordWithdraw:
		return "withdraw"
	default:
		return "unknown"
	}
}

type dampeningKey struct {
	peer   netip.Addr
	family bgp.Family
	prefix string
	pathID uint32
}

type dampeningInfo struct {
	key          dampeningKey
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
	reuseIndex   int
}

type dampeningManager struct {
	mu          sync.Mutex
	infos       map[dampeningKey]*dampeningInfo
	reuseLists  []map[dampeningKey]struct{}
	noReuseList map[dampeningKey]struct{}
	reuseOffset int
	now         func() time.Time
}

type dampeningSnapshot struct {
	neighbor       string
	family         bgp.Family
	prefix         string
	pathID         uint32
	penalty        int
	flap           int
	suppressed     bool
	lastRecord     dampeningRecordType
	startTime      time.Time
	updatedTime    time.Time
	suppressTime   time.Time
	reuseTime      time.Duration
	hasPendingPath bool
	config         oc.DampeningConfig
}

func newDampeningManager() *dampeningManager {
	reuseLists := make([]map[dampeningKey]struct{}, dampeningReuseListSize)
	for i := range reuseLists {
		reuseLists[i] = make(map[dampeningKey]struct{})
	}
	return &dampeningManager{
		infos:       make(map[dampeningKey]*dampeningInfo),
		reuseLists:  reuseLists,
		noReuseList: make(map[dampeningKey]struct{}),
		now:         time.Now,
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
	conf = normalizeDampeningConfigValue(conf)
	key := dampeningPathKey(path)
	now := m.now()
	cfg := newDampeningConfig(conf)

	m.mu.Lock()
	defer m.mu.Unlock()

	info := m.infos[key]
	if info != nil && info.configValue != conf {
		if info.config != nil && !info.updatedTime.IsZero() {
			info.penalty = info.config.decay(now.Sub(info.updatedTime), info.penalty)
			info.updatedTime = now
		}
		m.removeFromListsLocked(info)
		info.config = cfg
		info.configValue = conf
		m.updateHistoryListLocked(info)
	}
	if info == nil {
		info = &dampeningInfo{key: key, config: cfg, configValue: conf, reuseIndex: dampeningReuseIndexNone}
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

func (m *dampeningManager) reuseIndexLocked(info *dampeningInfo) int {
	if info == nil || info.config == nil || info.config.reuseLimit <= 0 || len(m.reuseLists) == 0 {
		return dampeningReuseIndexNone
	}
	cfg := info.config
	i := int((float64(info.penalty)/float64(cfg.reuseLimit) - 1.0) * cfg.scaleFactor)
	if i < 0 {
		i = 0
	}
	if i >= cfg.reuseIndexSize {
		i = cfg.reuseIndexSize - 1
	}
	index := cfg.reuseIndex[i] - cfg.reuseIndex[0]
	if index < 0 {
		index = 0
	}
	if cfg.reuseListSize > 0 && index >= cfg.reuseListSize {
		index %= cfg.reuseListSize
	}
	return (m.reuseOffset + index) % len(m.reuseLists)
}

func (m *dampeningManager) removeFromListsLocked(info *dampeningInfo) {
	if info == nil {
		return
	}
	if info.reuseIndex >= 0 && info.reuseIndex < len(m.reuseLists) {
		delete(m.reuseLists[info.reuseIndex], info.key)
	}
	if info.reuseIndex == dampeningNoReuseIndex {
		delete(m.noReuseList, info.key)
	}
	info.reuseIndex = dampeningReuseIndexNone
}

func (m *dampeningManager) addReuseListLocked(info *dampeningInfo) {
	if info == nil {
		return
	}
	m.removeFromListsLocked(info)
	index := m.reuseIndexLocked(info)
	if index < 0 || index >= len(m.reuseLists) {
		return
	}
	info.reuseIndex = index
	m.reuseLists[index][info.key] = struct{}{}
}

func (m *dampeningManager) addNoReuseListLocked(info *dampeningInfo) {
	if info == nil {
		return
	}
	m.removeFromListsLocked(info)
	info.reuseIndex = dampeningNoReuseIndex
	m.noReuseList[info.key] = struct{}{}
}

func (m *dampeningManager) updateHistoryListLocked(info *dampeningInfo) {
	if info == nil || info.config == nil || info.penalty <= 0 {
		m.removeFromListsLocked(info)
		return
	}
	if info.suppressed && info.penalty >= info.config.reuseLimit {
		m.addReuseListLocked(info)
		return
	}
	if info.penalty > info.config.reuseLimit/2 {
		m.addNoReuseListLocked(info)
		return
	}
	m.removeFromListsLocked(info)
}

func (m *dampeningManager) deleteInfoLocked(info *dampeningInfo) {
	if info == nil {
		return
	}
	m.removeFromListsLocked(info)
	delete(m.infos, info.key)
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
		m.updateHistoryListLocked(info)
		return nil
	}
	if info.penalty >= info.config.suppressValue {
		info.suppressed = true
		info.suppressTime = now
		m.addReuseListLocked(info)
	} else {
		m.updateHistoryListLocked(info)
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
			m.updateHistoryListLocked(info)
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
			m.updateHistoryListLocked(info)
			return []*table.Path{path}
		}
		info.pendingPath = path
		info.activePath = nil
		m.updateHistoryListLocked(info)
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
		m.addReuseListLocked(info)
		return []*table.Path{withdraw}
	}
	info.pendingPath = nil
	info.activePath = path
	if info.penalty <= info.config.reuseLimit/2 {
		info.penalty = 0
		info.flap = 0
		m.removeFromListsLocked(info)
	} else {
		m.addNoReuseListLocked(info)
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
	if len(m.reuseLists) == 0 {
		return paths
	}
	index := m.reuseOffset
	bucket := m.reuseLists[index]
	m.reuseLists[index] = make(map[dampeningKey]struct{})
	m.reuseOffset = (m.reuseOffset + 1) % len(m.reuseLists)

	for key := range bucket {
		info := m.infos[key]
		if info == nil || info.reuseIndex != index {
			continue
		}
		info.reuseIndex = dampeningReuseIndexNone
		if info.config == nil || info.updatedTime.IsZero() {
			continue
		}
		info.penalty = info.config.decay(now.Sub(info.updatedTime), info.penalty)
		info.updatedTime = now
		if !info.suppressed {
			m.updateHistoryListLocked(info)
			continue
		}
		if info.penalty >= info.config.reuseLimit {
			m.addReuseListLocked(info)
			continue
		}
		info.suppressed = false
		info.suppressTime = time.Time{}
		if info.lastRecord == dampeningRecordUpdate && info.pendingPath != nil {
			info.activePath = info.pendingPath
			paths = append(paths, info.pendingPath)
			info.pendingPath = nil
		}
		if info.penalty <= info.config.reuseLimit/2 {
			if info.activePath == nil {
				m.deleteInfoLocked(info)
				continue
			}
			info.penalty = 0
			info.flap = 0
			m.removeFromListsLocked(info)
		} else {
			m.addNoReuseListLocked(info)
		}
	}
	return paths
}

func (m *dampeningManager) snapshots(neighbor netip.Addr, family bgp.Family) []dampeningSnapshot {
	if m == nil {
		return nil
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshots := make([]dampeningSnapshot, 0, len(m.infos))
	for key, info := range m.infos {
		if neighbor.IsValid() && key.peer != neighbor {
			continue
		}
		if family != 0 && key.family != family {
			continue
		}
		if info == nil || info.config == nil {
			continue
		}
		penalty := info.penalty
		if !info.updatedTime.IsZero() {
			penalty = info.config.decay(now.Sub(info.updatedTime), penalty)
		}
		if penalty == 0 && info.flap == 0 && !info.suppressed {
			continue
		}
		snapshots = append(snapshots, dampeningSnapshot{
			neighbor:       key.peer.String(),
			family:         key.family,
			prefix:         key.prefix,
			pathID:         key.pathID,
			penalty:        penalty,
			flap:           info.flap,
			suppressed:     info.suppressed,
			lastRecord:     info.lastRecord,
			startTime:      info.startTime,
			updatedTime:    info.updatedTime,
			suppressTime:   info.suppressTime,
			reuseTime:      info.config.reuseTime(penalty),
			hasPendingPath: info.pendingPath != nil,
			config:         info.configValue,
		})
	}
	return snapshots
}

func (s *BgpServer) ListDampening(neighbor string, family bgp.Family, fn func(dampeningSnapshot)) error {
	if s == nil || s.dampening == nil {
		return nil
	}
	var addr netip.Addr
	if neighbor != "" {
		var err error
		addr, err = netip.ParseAddr(neighbor)
		if err != nil {
			return err
		}
	}
	if family != 0 && !dampeningFamilySupported(family) {
		return nil
	}
	for _, snapshot := range s.dampening.snapshots(addr, family) {
		fn(snapshot)
	}
	return nil
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
