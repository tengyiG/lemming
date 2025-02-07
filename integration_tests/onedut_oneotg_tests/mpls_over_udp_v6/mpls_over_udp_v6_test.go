// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License fbuildor the specific language governing permissions and
// limitations under the License.

package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/gribigo/client"
	"github.com/openconfig/gribigo/fluent"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"

	"github.com/openconfig/lemming/gnmi/fakedevice"
	"github.com/openconfig/lemming/gnmi/oc/ocpath"
	"github.com/openconfig/lemming/internal/attrs"
	"github.com/openconfig/lemming/internal/binding"
)

const (
	ipv4PrefixLen = 30
	ipv6PrefixLen = 99
)

var (
	dutPort1 = attrs.Attributes{
		Desc:    "dutPort1",
		IPv4:    "192.0.2.1",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001::aaaa:bbbb:aa",
		IPv6Len: ipv6PrefixLen,
	}

	atePort1 = attrs.Attributes{
		Name:    "port1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001::aaaa:bbbb:bb",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort2 = attrs.Attributes{
		Desc:    "dutPort2",
		IPv4:    "192.0.2.5",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001::aaab:bbbb:aa",
		IPv6Len: ipv6PrefixLen,
	}

	atePort2 = attrs.Attributes{
		Name:    "port2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001::aaab:bbbb:bb",
		IPv6Len: ipv6PrefixLen,
	}
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, binding.KNE(".."))
}

// configureDUT configures port1 and port2 on the DUT.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	p1 := dut.Port(t, "port1")
	gnmi.Replace(t, dut, ocpath.Root().Interface(p1.Name()).Config(), dutPort1.NewOCInterface(p1.Name(), dut))

	p2 := dut.Port(t, "port2")
	gnmi.Replace(t, dut, ocpath.Root().Interface(p2.Name()).Config(), dutPort2.NewOCInterface(p2.Name(), dut))

	gnmi.Await(t, dut, ocpath.Root().Interface(dut.Port(t, "port1").Name()).Subinterface(0).Ipv4().Address(dutPort1.IPv4).Ip().State(), time.Minute, dutPort1.IPv4)
	gnmi.Await(t, dut, ocpath.Root().Interface(dut.Port(t, "port2").Name()).Subinterface(0).Ipv4().Address(dutPort2.IPv4).Ip().State(), time.Minute, dutPort2.IPv4)
	gnmi.Await(t, dut, ocpath.Root().Interface(dut.Port(t, "port1").Name()).Subinterface(0).Ipv6().Address(dutPort1.IPv6).Ip().State(), time.Minute, dutPort1.IPv6)
	gnmi.Await(t, dut, ocpath.Root().Interface(dut.Port(t, "port2").Name()).Subinterface(0).Ipv6().Address(dutPort2.IPv6).Ip().State(), time.Minute, dutPort2.IPv6)
}

// configureOTG configures port1 and port2 on the ATE.
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	top := gosnappi.NewConfig()

	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	atePort1.AddToOTG(top, p1, &dutPort1)
	atePort2.AddToOTG(top, p2, &dutPort2)

	return top
}

const (
	// IPv4
	ateDstNetCIDRv4 = "198.51.100.0/24"
	// IPv6
	ateDstNetCIDRv6     = "2001:db8::/64" // Example prefix, adjust as needed
	ateIndirectNHv6     = "2001:db8:1::1" // Example indirect next hop, adjust as needed
	ateIndirectNHCIDRv6 = ateIndirectNHv6 + "/128"
	// Common attributes
	nhIndex         = 1
	nhgIndex        = 42
	nhIndex2        = 2
	nhgIndex2       = 52
	nhIndex3        = 3
	nhgIndex3       = 62
	mplsLabel       = uint64(100)     // Example MPLS label
	outerDstUDPPort = uint64(6635)    // Example UDP port
	outerIPv6Src    = "2001:f:a:1::0" // Example outer IPv6 src, adjust as needed
	outerIPv6Dst    = "2001:f:c:e::2" // Example outer IPv6 dst, adjust as needed
	ipTTL           = 1
)

// ateIndirectNH     = ateIndirectNHv4
// ateDstNetCIDR     = ateDstNetCIDRv4
// ateIndirectNHCIDR = ateIndirectNHCIDRv4
var destIP = atePort2.IPv6

// awaitTimeout calls a fluent client Await, adding a timeout to the context.
func awaitTimeout(ctx context.Context, c *fluent.GRIBIClient, t testing.TB, timeout time.Duration) error {
	subctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Await(subctx, t)
}

func TestMPLSOverUDPIPv6(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)

	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t, ate)
	otg.PushConfig(t, otgConfig)
	// network_instances: {
	//   network_instance: {
	//     afts {
	//       #
	//       # entries used for "group_A"
	//       ipv6_unicast {
	//         ipv6_entry {
	//           prefix: "inner_ipv6_dst_A"   # this is an IPv6 entry for the origin/inner packet.
	//           next_hop_group: 100
	//         }
	//       }
	//       ipv4_unicast {
	//         ipv4_entry {
	//           prefix: "ipv4_inner_dst_A"   # this is an IPv4 entry for the origin/inner packet.
	//           next_hop_group: 100
	//         }
	//       }
	//       next_hop_groups {
	//         next_hop_group {
	//           id: 100
	//           next_hops {            # reference to a next-hop
	//             next_hop: {
	//               index: 100
	//             }
	//           }
	//         }
	//       }
	//       next_hops {
	//         next_hop {
	//           index: 100
	//           network_instance: "group_A"
	//           encap-headers {
	//             encap-header {
	//               index: 1
	//               pushed_mpls_label_stack: [100,]
	//             }
	//           }
	//           encap-headers {
	//             encap-header {
	//               index: 2
	//               src_ip: "outer_ipv6_src"
	//               dst_ip: "outer_ipv6_dst_A"
	//               dst_udp_port: "outer_dst_udp_port"
	//               ip_ttl: "outer_ip-ttl"
	//               dscp: "outer_dscp"
	//             }
	//           }
	//         }
	//       }
	//       #
	//       # entries used for "group_B"
	//       ipv6_unicast {
	//         ipv6_entry {
	//           prefix: "inner_ipv6_dst_B"
	//           next_hop_group: 200
	//         }
	//       }
	//       ipv4_unicast {
	//         ipv4_entry {
	//           prefix: "ipv4_inner_dst_B"
	//           next_hop_group: 200
	//         }
	//       }
	//       next_hop_groups {
	//         next_hop_group {
	//           id: 200
	//           next_hops {            # reference to a next-hop
	//             next_hop: {
	//               index: 200
	//             }
	//           }
	//         }
	//       }
	//       next_hops {
	//         next_hop {
	//           index: 200
	//           network_instance: "group_B"
	//           encap-headers {
	//             encap-header {
	//               index: 1
	//               type : OPENCONFIG_AFT_TYPES:MPLS
	//               mpls {
	//                 pushed_mpls_label_stack: [200,]
	//               }
	//             }
	//           }
	//           encap-headers {
	//             encap-header {
	//               index: 2
	//               type: OPENCONFIG_AFT_TYPES:UDP
	//               udp {
	//                 src_ip: "outer_ipv6_src"
	//                 dst_ip: "outer_ipv6_dst_B"
	//                 dst_udp_port: "outer_dst_udp_port"
	//                 ip_ttl: "outer_ip-ttl"
	//                 dscp: "outer_dscp"
	//               }
	//             }
	//           }
	//         }
	//       }
	//     }
	//   }
	// }
	tests := []struct {
		desc                    string
		entries                 []fluent.GRIBIEntry
		wantAddOperationResults []*client.OpResult
	}{
		{
			desc: "update-aft test",
			entries: []fluent.GRIBIEntry{
				fluent.IPv6Entry().WithNetworkInstance(fakedevice.DefaultNetworkInstance).
					WithPrefix(ateDstNetCIDRv6).WithNextHopGroup(nhgIndex),
				fluent.IPv4Entry().WithNetworkInstance(fakedevice.DefaultNetworkInstance).
					WithPrefix(ateDstNetCIDRv4).WithNextHopGroup(nhgIndex),
				fluent.NextHopGroupEntry().WithNetworkInstance(fakedevice.DefaultNetworkInstance).
					WithID(nhgIndex).AddNextHop(nhIndex, 1),
				// fluent.NextHopEntry().WithNetworkInstance(fakedevice.DefaultNetworkInstance).
				// 	WithIndex(nhIndex).WithIPAddress(destIP).AddEncapHeader(
				// 	fluent.MPLSEncapHeader().WithLabels(mplsLabel),
				// 	fluent.UDPV6EncapHeader().WithDstUDPPort(outerDstUDPPort).WithSrcUDPPort(outerDstUDPPort),
				// ),
			},
			wantAddOperationResults: []*client.OpResult{
				fluent.OperationResult().AsResult(),
				fluent.OperationResult().AsResult(),
				fluent.OperationResult().AsResult(),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			gribic := dut.RawAPIs().GRIBI(t)
			c := fluent.NewClient()
			c.Connection().WithStub(gribic).
				WithRedundancyMode(fluent.ElectedPrimaryClient).
				WithPersistence().
				WithFIBACK().
				WithInitialElectionID(1, 0)
			ctx := context.Background()
			c.Start(ctx, t)
			defer c.Stop(t)
			c.StartSending(ctx, t)
			if err := awaitTimeout(ctx, c, t, time.Minute); err != nil {
				t.Fatalf("Await got error during session negotiation: %v", err)
			}

			c.Modify().AddEntry(t, tc.entries...)
			if err := awaitTimeout(ctx, c, t, time.Minute); err != nil {
				t.Fatalf("Await got error for entries: %v", err)
			}

			for _, wantResult := range tc.wantAddOperationResults {
				t.Logf("c.Results: %v", c.Results(t))
				t.Logf("wantResult: %v\n\n", wantResult)
			}
		})
	}
}
