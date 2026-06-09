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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func formatDampeningDuration(seconds uint64) string {
	if seconds == 0 {
		return "00:00:00"
	}
	duration := time.Duration(seconds) * time.Second
	total := int64(duration.Seconds())
	days := total / 86400
	total %= 86400
	hours := total / 3600
	total %= 3600
	minutes := total / 60
	seconds = uint64(total % 60)
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func dampeningFamilyString(f *api.Family) string {
	if f == nil {
		return "-"
	}
	return bgp.NewFamily(uint16(f.Afi), uint8(f.Safi)).String()
}

func dampeningBoolString(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func showDampening(neighbor string) error {
	var family *api.Family
	if subOpts.AddressFamily != "" {
		var err error
		family, err = checkAddressFamily(nil)
		if err != nil {
			return err
		}
	}
	stream, err := client.ListDampening(ctx, &api.ListDampeningRequest{
		Neighbor: neighbor,
		Family:   family,
	})
	if err != nil {
		return err
	}

	infos := make([]*api.DampeningInfo, 0)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if r.Info != nil {
			infos = append(infos, r.Info)
		}
	}

	if globalOpts.Json {
		j, _ := json.MarshalIndent(infos, "", "  ")
		fmt.Println(string(j))
		return nil
	}
	if len(infos) == 0 {
		fmt.Println("No dampening information")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Neighbor\tFamily\tPrefix\tPathID\tPenalty\tFlaps\tSuppressed\tReuse\tPending\tLast\tHalfLife\tReuseThr\tSuppressThr\tMaxSuppress")
	for _, info := range infos {
		cfg := info.GetConfig()
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			info.GetNeighbor(),
			dampeningFamilyString(info.GetFamily()),
			info.GetPrefix(),
			info.GetPathId(),
			info.GetPenalty(),
			info.GetFlapCount(),
			dampeningBoolString(info.GetSuppressed()),
			formatDampeningDuration(info.GetReuseTime()),
			dampeningBoolString(info.GetHasPendingPath()),
			info.GetLastRecord(),
			cfg.GetHalfLife(),
			cfg.GetReuseThreshold(),
			cfg.GetSuppressThreshold(),
			cfg.GetMaxSuppressTime(),
		)
	}
	return w.Flush()
}
