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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func newDampeningTestPath(t *testing.T, prefix string, med uint32, withdraw bool) *table.Path {
	t.Helper()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath(nil),
		bgp.NewPathAttributeMultiExitDisc(med),
	}
	if withdraw {
		attrs = nil
	}
	return table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{
		PeerType: oc.PEER_TYPE_EXTERNAL,
		AS:       65001,
		LocalAS:  65000,
		ID:       netip.MustParseAddr("192.0.2.1"),
		LocalID:  netip.MustParseAddr("192.0.2.254"),
		Address:  netip.MustParseAddr("192.0.2.1"),
	}, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Unix(0, 0), false)
}

func TestDampeningManagerSuppressesAndReusesWithdrawFlaps(t *testing.T) {
	now := time.Unix(100, 0)
	m := newDampeningManager()
	m.now = func() time.Time { return now }
	conf := oc.DampeningConfig{
		Enabled:           true,
		HalfLife:          1,
		ReuseThreshold:    750,
		SuppressThreshold: 2000,
		MaxSuppressTime:   4,
	}

	path := newDampeningTestPath(t, "203.0.113.0/24", 100, false)
	require.Equal(t, []*table.Path{path}, m.apply(path, conf))

	withdraw1 := path.Clone(true)
	out := m.apply(withdraw1, conf)
	require.Len(t, out, 1)
	require.True(t, out[0].IsWithdraw)

	update1 := newDampeningTestPath(t, "203.0.113.0/24", 100, false)
	require.Equal(t, []*table.Path{update1}, m.apply(update1, conf))

	withdraw2 := update1.Clone(true)
	out = m.apply(withdraw2, conf)
	require.Len(t, out, 1)
	require.True(t, out[0].IsWithdraw)

	update2 := newDampeningTestPath(t, "203.0.113.0/24", 200, false)
	require.Empty(t, m.apply(update2, conf))

	now = now.Add(2 * time.Minute)
	reused := m.tick()
	require.Len(t, reused, 1)
	require.Equal(t, update2, reused[0])
	require.False(t, reused[0].IsWithdraw)
}

func TestDampeningManagerSuppressesAttributeChanges(t *testing.T) {
	now := time.Unix(200, 0)
	m := newDampeningManager()
	m.now = func() time.Time { return now }
	conf := oc.DampeningConfig{
		Enabled:           true,
		HalfLife:          1,
		ReuseThreshold:    1,
		SuppressThreshold: 1,
		MaxSuppressTime:   1,
	}

	path := newDampeningTestPath(t, "198.51.100.0/24", 100, false)
	require.Equal(t, []*table.Path{path}, m.apply(path, conf))

	changed := newDampeningTestPath(t, "198.51.100.0/24", 200, false)
	out := m.apply(changed, conf)
	require.Len(t, out, 1)
	require.True(t, out[0].IsWithdraw)

	require.Empty(t, m.apply(changed, conf))

	now = now.Add(70 * time.Second)
	reused := m.tick()
	require.Len(t, reused, 1)
	require.Equal(t, changed, reused[0])
}
