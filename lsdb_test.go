// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lsdbparse

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/lsdbparse/pkg/oc"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// Helper function to return a float32 as a byte slice. We use big endian
// to reflect network byte order.
func float32ByteSlice(f float32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, math.Float32bits(f))
	return b
}

func mustPath(s string) *gnmipb.Path {
	p, err := ygot.StringToStructuredPath(s)
	if err != nil {
		panic(err)
	}
	return p
}

func mustTypedValue(i interface{}) *gnmipb.TypedValue {
	v, err := value.FromScalar(i)
	if err != nil {
		panic(err)
	}
	return v
}

func TestISISBytesToLSP(t *testing.T) {
	// A lab example.
	var err error
	ex1, err := hex.DecodeString(strings.Replace("00:00:40:00:ce:39:00:00:00:00:14:26:27:7f:03:01:0e:0d:39:75:2f:01:00:00:14:00:00:90:00:00:01:0e:02:05:d4:81:02:cc:8e:86:04:0a:f4:a8:1f:84:04:0a:f4:a8:1f:89:0e:72:65:30:2d:70:72:30:35:2e:73:71:6c:38:38:16:4f:00:00:40:00:ce:39:02:00:00:1e:44:06:04:c0:a8:c9:24:04:08:00:00:01:43:00:00:00:00:0b:20:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:0a:04:4e:ee:6b:28:09:04:4f:15:02:f9:03:04:00:00:00:00:ec:24:00:00:00:00:00:80:26:07:f8:b0:00:00:00:00:00:00:00:03:40:00:ce:39:00:00:00:1e:00:40:20:01:48:60:c0:a8:c9:20:87:12:00:00:00:00:20:0a:f4:a8:1f:00:00:00:1e:1b:c0:a8:c9:20:f2:05:0a:f4:a8:1f:01", ":", "", -1))
	// A more detailed example.
	ex2, err := hex.DecodeString(strings.Replace("00:00:40:00:ce:39:02:00:00:00:0e:40:91:bf:03:16:21:00:00:40:00:ce:39:00:00:00:00:00:00:00:40:00:ce:3b:00:00:00:00:00:00:00:40:00:ce:3a:00:00:00:00:00", ":", "", -1))

	// A larger IS-IS PDU.
	ex3, err := hex.DecodeString(strings.Replace("00:00:40:00:ce:3a:00:00:00:00:18:09:f1:2e:03:01:0e:0d:39:75:2f:01:00:00:14:00:00:90:00:00:01:0e:02:05:d4:81:02:cc:8e:86:04:0a:f4:a8:09:84:04:0a:f4:a8:09:89:0e:72:65:30:2d:62:62:30:37:2e:73:71:6c:38:38:16:cc:00:00:40:00:ce:39:02:00:00:1e:5e:06:04:c0:a8:c9:23:04:08:00:00:00:44:00:00:00:00:0b:20:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:0a:04:4e:ee:6b:28:09:04:4f:15:02:f9:03:04:00:00:00:00:20:0b:30:00:00:00:40:00:ce:39:00:00:16:20:0b:b0:00:00:00:40:00:ce:39:00:00:17:00:00:40:00:ce:3c:00:00:00:0a:58:06:04:c0:a8:c8:08:08:04:c0:a8:c8:09:04:08:00:00:00:47:00:00:01:00:0b:20:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:66:94:4e:ee:66:94:4e:ee:66:94:0a:04:4e:ee:6b:28:09:04:4f:15:02:f9:03:04:00:00:00:00:1f:05:30:00:00:00:14:1f:05:b0:00:00:00:15:16:c6:00:00:40:00:d5:b8:00:00:2e:ea:58:06:04:c0:a8:c8:30:08:04:c0:a8:c8:31:04:08:00:00:00:48:00:00:00:59:0b:20:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:4e:6e:6b:28:0a:04:4e:6e:6b:28:09:04:4e:95:02:f9:03:04:40:00:00:00:1f:05:30:00:00:00:12:1f:05:b0:00:00:00:13:00:00:40:00:d5:be:00:00:00:0a:58:06:04:c0:a8:c8:0e:08:04:c0:a8:c8:0f:04:08:00:00:00:49:00:00:01:48:0b:20:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:6b:28:4e:ee:5b:e6:4e:ee:5b:e6:4e:ee:5b:e6:0a:04:4e:ee:6b:28:09:04:4f:15:02:f9:03:04:00:00:00:00:1f:05:30:00:00:00:10:1f:05:b0:00:00:00:11:87:51:00:00:00:1e:1b:c0:a8:c9:20:00:00:00:0a:1f:c0:a8:c8:08:00:00:2e:ea:1f:c0:a8:c8:30:00:00:00:0a:1f:c0:a8:c8:0e:00:00:00:00:20:0a:f4:a8:09:00:00:00:00:60:64:01:01:0d:08:03:06:40:00:00:00:00:c8:00:00:00:00:60:c8:01:01:08:08:03:06:00:00:00:00:75:30:84:08:64:01:01:0d:c8:01:01:08:ec:a4:00:00:00:1e:00:40:20:01:48:60:c0:a8:c9:20:00:00:00:0a:00:7f:20:01:00:00:00:00:48:60:01:92:01:68:02:00:00:08:00:00:2e:ea:00:7f:20:01:00:00:00:00:48:60:01:92:01:68:02:00:00:48:00:00:00:0a:00:7f:20:01:00:00:00:00:48:60:01:92:01:68:02:00:00:14:00:00:00:00:00:80:26:07:f8:b0:00:00:00:00:00:00:00:01:40:00:ce:3a:00:00:00:00:20:80:26:07:f8:b0:00:00:00:00:01:00:00:01:00:01:00:13:08:03:06:40:00:00:00:04:b0:00:00:00:00:20:80:26:07:f8:b0:00:00:00:00:02:00:00:01:00:01:00:08:08:03:06:00:00:00:00:79:18:f2:13:0a:f4:a8:09:00:02:09:c0:00:fd:e9:01:03:06:1a:80:13:01:00", ":", "", -1))

	if err != nil {
		t.Fatalf("TestISISBytesToLSP: couldn't decode a static example: %v", err)
	}

	tests := []struct {
		name         string
		inBytes      []byte
		inOffset     int
		wantLSP      *oc.Lsp
		wantFatalErr bool
	}{{
		name:         "invalid data",
		inBytes:      []byte{0x01, 0x2},
		wantFatalErr: true,
	}, {
		name:    "vendor c example #1",
		inBytes: ex1,
		wantLSP: &oc.Lsp{
			Checksum:       ygot.Uint16(10111),
			LspId:          ygot.String("0000.4000.ce39.00-00"),
			SequenceNumber: ygot.Uint32(5158),
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
					AreaAddress: &oc.Lsp_Tlv_AreaAddress{
						Address: []string{"39.752f.0100.0014.0000.9000.0001"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
					Ipv4TeRouterId: &oc.Lsp_Tlv_Ipv4TeRouterId{
						RouterId: []string{"10.244.168.31"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
					Ipv6Reachability: &oc.Lsp_Tlv_Ipv6Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_Ipv6Reachability_Prefix{
							"2607:f8b0::3:4000:ce39/128": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("2607:f8b0::3:4000:ce39/128"),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"2001:4860:c0a8:c920::/64": {
								Metric: ygot.Uint32(30),
								Prefix: ygot.String("2001:4860:c0a8:c920::/64"),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
					Nlpid: &oc.Lsp_Tlv_Nlpid{
						Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV4,
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV6,
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
					Capability: map[uint32]*oc.Lsp_Tlv_Capability{
						0: {
							InstanceNumber: ygot.Uint32(0),
							RouterId:       ygot.String("10.244.168.31"),
							Flags: []oc.E_OpenconfigIsis_Capability_Flags{
								oc.OpenconfigIsis_Capability_Flags_FLOOD,
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
					Hostname: &oc.Lsp_Tlv_Hostname{
						Hostname: []string{"re0-pr05.sql88"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
					ExtendedIpv4Reachability: &oc.Lsp_Tlv_ExtendedIpv4Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
							"10.244.168.31/32": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("10.244.168.31/32"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"192.168.201.32/27": {
								Metric: ygot.Uint32(30),
								Prefix: ygot.String("192.168.201.32/27"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
					ExtendedIsReachability: &oc.Lsp_Tlv_ExtendedIsReachability{
						Neighbor: map[string]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor{
							"0000.4000.ce39.02": {
								SystemId: ygot.String("0000.4000.ce39.02"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(30),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
												AdminGroup: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
													AdminGroup: []uint32{0},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.201.36"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
												MaxLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
													Bandwidth: float32ByteSlice(2.5e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(2e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH,
												SetupPriority: map[uint8]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
													0: {Priority: ygot.Uint8(0), Bandwidth: float32ByteSlice(16000000000 / 8)},
													1: {Priority: ygot.Uint8(1), Bandwidth: float32ByteSlice(16000000000 / 8)},
													2: {Priority: ygot.Uint8(2), Bandwidth: float32ByteSlice(16000000000 / 8)},
													3: {Priority: ygot.Uint8(3), Bandwidth: float32ByteSlice(16000000000 / 8)},
													4: {Priority: ygot.Uint8(4), Bandwidth: float32ByteSlice(16000000000 / 8)},
													5: {Priority: ygot.Uint8(5), Bandwidth: float32ByteSlice(16000000000 / 8)},
													6: {Priority: ygot.Uint8(6), Bandwidth: float32ByteSlice(16000000000 / 8)},
													7: {Priority: ygot.Uint8(7), Bandwidth: float32ByteSlice(16000000000 / 8)},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID,
												LinkId: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
													Local:  ygot.Uint32(323),
													Remote: ygot.Uint32(0),
												},
											},
										},
									},
								},
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES,
					Ipv4InterfaceAddresses: &oc.Lsp_Tlv_Ipv4InterfaceAddresses{
						Address: []string{"10.244.168.31"},
					},
				},
			},
		},
	}, {
		name:    "example #2",
		inBytes: ex2,
		wantLSP: &oc.Lsp{
			Checksum:       ygot.Uint16(37311),
			LspId:          ygot.String("0000.4000.ce39.02-00"),
			SequenceNumber: ygot.Uint32(3648),
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
					ExtendedIsReachability: &oc.Lsp_Tlv_ExtendedIsReachability{
						Neighbor: map[string]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor{
							"0000.4000.ce39.00": {
								SystemId: ygot.String("0000.4000.ce39.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(0),
									},
								},
							},
							"0000.4000.ce3a.00": {
								SystemId: ygot.String("0000.4000.ce3a.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(0),
									},
								},
							},
							"0000.4000.ce3b.00": {
								SystemId: ygot.String("0000.4000.ce3b.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(0),
									},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name:    "example #3",
		inBytes: ex3,
		wantLSP: &oc.Lsp{
			Checksum:       ygot.Uint16(61742),
			LspId:          ygot.String("0000.4000.ce3a.00-00"),
			SequenceNumber: ygot.Uint32(6153),
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
					AreaAddress: &oc.Lsp_Tlv_AreaAddress{
						Address: []string{"39.752f.0100.0014.0000.9000.0001"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
					Nlpid: &oc.Lsp_Tlv_Nlpid{
						Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV4,
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV6,
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
					Ipv4TeRouterId: &oc.Lsp_Tlv_Ipv4TeRouterId{
						RouterId: []string{"10.244.168.9"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES,
					Ipv4InterfaceAddresses: &oc.Lsp_Tlv_Ipv4InterfaceAddresses{
						Address: []string{
							"10.244.168.9",
							"100.1.1.13",
							"200.1.1.8",
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
					Hostname: &oc.Lsp_Tlv_Hostname{
						Hostname: []string{"re0-bb07.sql88"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
					ExtendedIsReachability: &oc.Lsp_Tlv_ExtendedIsReachability{
						Neighbor: map[string]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor{
							"0000.4000.ce39.02": {
								SystemId: ygot.String("0000.4000.ce39.02"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(30),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.201.35"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(2e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
												MaxLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
													Bandwidth: float32ByteSlice(2.5e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
												AdminGroup: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
													AdminGroup: []uint32{0},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH,
												SetupPriority: map[uint8]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
													0: {Priority: ygot.Uint8(0), Bandwidth: float32ByteSlice(16000000000 / 8)},
													1: {Priority: ygot.Uint8(1), Bandwidth: float32ByteSlice(16000000000 / 8)},
													2: {Priority: ygot.Uint8(2), Bandwidth: float32ByteSlice(16000000000 / 8)},
													3: {Priority: ygot.Uint8(3), Bandwidth: float32ByteSlice(16000000000 / 8)},
													4: {Priority: ygot.Uint8(4), Bandwidth: float32ByteSlice(16000000000 / 8)},
													5: {Priority: ygot.Uint8(5), Bandwidth: float32ByteSlice(16000000000 / 8)},
													6: {Priority: ygot.Uint8(6), Bandwidth: float32ByteSlice(16000000000 / 8)},
													7: {Priority: ygot.Uint8(7), Bandwidth: float32ByteSlice(16000000000 / 8)},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_LAN_SID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_LAN_SID,
												LanAdjacencySid: map[uint32]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
													22: {
														Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
															oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
														},
														NeighborId: ygot.String("0000.4000.ce39"),
														Value:      ygot.Uint32(22),
														Weight:     ygot.Uint8(0),
													},
													23: {
														Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
															oc.OpenconfigIsis_LanAdjacencySid_Flags_ADDRESS_FAMILY,
															oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
														},
														NeighborId: ygot.String("0000.4000.ce39"),
														Value:      ygot.Uint32(23),
														Weight:     ygot.Uint8(0),
													},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID,
												LinkId: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
													Local:  ygot.Uint32(68),
													Remote: ygot.Uint32(0),
												},
											},
										},
									},
								},
							},
							"0000.4000.ce3c.00": {
								SystemId: ygot.String("0000.4000.ce3c.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(10),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.200.8"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS,
												Ipv4NeighborAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4NeighborAddress{
													Address: []string{"192.168.200.9"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(2e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
												MaxLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
													Bandwidth: float32ByteSlice(2.5e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
												AdminGroup: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
													AdminGroup: []uint32{0},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH,
												SetupPriority: map[uint8]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
													0: {Priority: ygot.Uint8(0), Bandwidth: float32ByteSlice(16000000000 / 8)},
													1: {Priority: ygot.Uint8(1), Bandwidth: float32ByteSlice(16000000000 / 8)},
													2: {Priority: ygot.Uint8(2), Bandwidth: float32ByteSlice(16000000000 / 8)},
													3: {Priority: ygot.Uint8(3), Bandwidth: float32ByteSlice(16000000000 / 8)},
													4: {Priority: ygot.Uint8(4), Bandwidth: float32ByteSlice(16000000000 / 8)},
													5: {Priority: ygot.Uint8(5), Bandwidth: float32ByteSlice(15998799872 / 8)},
													6: {Priority: ygot.Uint8(6), Bandwidth: float32ByteSlice(15998799872 / 8)},
													7: {Priority: ygot.Uint8(7), Bandwidth: float32ByteSlice(15998799872 / 8)},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID,
												AdjacencySid: map[uint32]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
													20: {
														Value:  ygot.Uint32(20),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
													21: {
														Value:  ygot.Uint32(21),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY,
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID,
												LinkId: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
													Local:  ygot.Uint32(71),
													Remote: ygot.Uint32(256),
												},
											},
										},
									},
								},
							},
							"0000.4000.d5be.00": {
								SystemId: ygot.String("0000.4000.d5be.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(10),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.200.14"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS,
												Ipv4NeighborAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4NeighborAddress{
													Address: []string{"192.168.200.15"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(2e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
												MaxLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
													Bandwidth: float32ByteSlice(2.5e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
												AdminGroup: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
													AdminGroup: []uint32{0},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH,
												SetupPriority: map[uint8]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
													0: {Priority: ygot.Uint8(0), Bandwidth: float32ByteSlice(16000000000 / 8)},
													1: {Priority: ygot.Uint8(1), Bandwidth: float32ByteSlice(16000000000 / 8)},
													2: {Priority: ygot.Uint8(2), Bandwidth: float32ByteSlice(16000000000 / 8)},
													3: {Priority: ygot.Uint8(3), Bandwidth: float32ByteSlice(16000000000 / 8)},
													4: {Priority: ygot.Uint8(4), Bandwidth: float32ByteSlice(16000000000 / 8)},
													5: {Priority: ygot.Uint8(5), Bandwidth: float32ByteSlice(15996000256 / 8)},
													6: {Priority: ygot.Uint8(6), Bandwidth: float32ByteSlice(15996000256 / 8)},
													7: {Priority: ygot.Uint8(7), Bandwidth: float32ByteSlice(15996000256 / 8)},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID,
												AdjacencySid: map[uint32]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
													16: {
														Value:  ygot.Uint32(16),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
													17: {
														Value:  ygot.Uint32(17),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY,
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID,
												LinkId: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
													Local:  ygot.Uint32(73),
													Remote: ygot.Uint32(328),
												},
											},
										},
									},
								},
							},
							"0000.4000.d5b8.00": {
								SystemId: ygot.String("0000.4000.d5b8.00"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(12010),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.200.48"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS,
												Ipv4NeighborAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4NeighborAddress{
													Address: []string{"192.168.200.49"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(1e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
												MaxLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
													Bandwidth: float32ByteSlice(1.25e9),
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
												AdminGroup: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
													AdminGroup: []uint32{1073741824},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH,
												SetupPriority: map[uint8]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
													0: {Priority: ygot.Uint8(0), Bandwidth: float32ByteSlice(8000000000 / 8)},
													1: {Priority: ygot.Uint8(1), Bandwidth: float32ByteSlice(8000000000 / 8)},
													2: {Priority: ygot.Uint8(2), Bandwidth: float32ByteSlice(8000000000 / 8)},
													3: {Priority: ygot.Uint8(3), Bandwidth: float32ByteSlice(8000000000 / 8)},
													4: {Priority: ygot.Uint8(4), Bandwidth: float32ByteSlice(8000000000 / 8)},
													5: {Priority: ygot.Uint8(5), Bandwidth: float32ByteSlice(8000000000 / 8)},
													6: {Priority: ygot.Uint8(6), Bandwidth: float32ByteSlice(8000000000 / 8)},
													7: {Priority: ygot.Uint8(7), Bandwidth: float32ByteSlice(8000000000 / 8)},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID,
												AdjacencySid: map[uint32]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
													18: {
														Value:  ygot.Uint32(18),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
													19: {
														Value:  ygot.Uint32(19),
														Weight: ygot.Uint8(0),
														Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
															oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY,
															oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
															oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
														},
													},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID,
												LinkId: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
													Local:  ygot.Uint32(72),
													Remote: ygot.Uint32(89),
												},
											},
										},
									},
								},
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
					ExtendedIpv4Reachability: &oc.Lsp_Tlv_ExtendedIpv4Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
							"192.168.201.32/27": {
								Metric: ygot.Uint32(30),
								Prefix: ygot.String("192.168.201.32/27"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"192.168.200.8/31": {
								Metric: ygot.Uint32(10),
								Prefix: ygot.String("192.168.200.8/31"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"192.168.200.48/31": {
								Metric: ygot.Uint32(12010),
								Prefix: ygot.String("192.168.200.48/31"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"192.168.200.14/31": {
								Metric: ygot.Uint32(10),
								Prefix: ygot.String("192.168.200.14/31"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"10.244.168.9/32": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("10.244.168.9/32"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"100.1.1.13/32": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("100.1.1.13/32"),
								SBit:   ygot.Bool(true),
								UpDown: ygot.Bool(false),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
										PrefixSid: map[uint32]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv_PrefixSid{
											200: {
												Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
													oc.OpenconfigIsis_PrefixSid_Flags_NODE,
												},
												Algorithm: ygot.Uint8(0),
												Value:     ygot.Uint32(200),
											},
										},
									},
								},
							},
							"200.1.1.8/32": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("200.1.1.8/32"),
								SBit:   ygot.Bool(true),
								UpDown: ygot.Bool(false),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
										PrefixSid: map[uint32]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv_PrefixSid{
											30000: {
												Algorithm: ygot.Uint8(0),
												Value:     ygot.Uint32(30000),
											},
										},
									},
								},
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
					Capability: map[uint32]*oc.Lsp_Tlv_Capability{
						0: {
							RouterId:       ygot.String("10.244.168.9"),
							InstanceNumber: ygot.Uint32(0),
							Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_Capability_Subtlv{
								oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_ALGORITHM: {
									Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_ALGORITHM,
									SegmentRoutingAlgorithms: &oc.Lsp_Tlv_Capability_Subtlv_SegmentRoutingAlgorithms{
										Algorithm: []oc.E_OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm{oc.OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm_SPF},
									},
								},

								oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_CAPABILITY: {
									Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_CAPABILITY,
									SegmentRoutingCapability: &oc.Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability{
										Flags: []oc.E_OpenconfigIsis_SegmentRoutingCapability_Flags{
											oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV4_MPLS,
											oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV6_MPLS,
										},
										SrgbDescriptor: map[uint32]*oc.Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor{
											0: {
												Label: &oc.Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor_Label_Union_Uint32{400000},
												Range: ygot.Uint32(65001),
											},
										},
									},
								},
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
					Ipv6Reachability: &oc.Lsp_Tlv_Ipv6Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_Ipv6Reachability_Prefix{
							"2001:4860:c0a8:c920::/64": {
								Prefix: ygot.String("2001:4860:c0a8:c920::/64"),
								Metric: ygot.Uint32(30),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
							},
							"2001::4860:192:168:200:8/127": {
								Prefix: ygot.String("2001::4860:192:168:200:8/127"),
								Metric: ygot.Uint32(10),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
							},
							"2001::4860:192:168:200:48/127": {
								Prefix: ygot.String("2001::4860:192:168:200:48/127"),
								Metric: ygot.Uint32(12010),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
							},
							"2001::4860:192:168:200:14/127": {
								Prefix: ygot.String("2001::4860:192:168:200:14/127"),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(false),
								Metric: ygot.Uint32(10),
								XBit:   ygot.Bool(false),
							},
							"2607:f8b0::1:4000:ce3a/128": {
								Prefix: ygot.String("2607:f8b0::1:4000:ce3a/128"),
								Metric: ygot.Uint32(0),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
							},
							"2607:f8b0::100:1:1:13/128": {
								Prefix: ygot.String("2607:f8b0::100:1:1:13/128"),
								Metric: ygot.Uint32(0),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(true),
								XBit:   ygot.Bool(false),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
										PrefixSid: map[uint32]*oc.Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv_PrefixSid{
											1200: {
												Algorithm: ygot.Uint8(0),
												Value:     ygot.Uint32(1200),
												Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
													oc.OpenconfigIsis_PrefixSid_Flags_NODE,
												},
											},
										},
									},
								},
							},
							"2607:f8b0::200:1:1:8/128": {
								Prefix: ygot.String("2607:f8b0::200:1:1:8/128"),
								Metric: ygot.Uint32(0),
								UpDown: ygot.Bool(false),
								SBit:   ygot.Bool(true),
								XBit:   ygot.Bool(false),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
										PrefixSid: map[uint32]*oc.Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv_PrefixSid{
											31000: {
												Algorithm: ygot.Uint8(0),
												Value:     ygot.Uint32(31000),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}}

	for _, tt := range tests {
		got, parsed, err := ISISBytesToLSP(tt.inBytes, tt.inOffset)
		if !parsed {
			if !tt.wantFatalErr {
				t.Errorf("%s: ISISBytesToLSP(...): got fatal error: %v", tt.name, err)
			}
			continue
		}
		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: ISISBytesToLSP(...): did not get expected LSP, diff(-got,+want):\n%s\nnon-fatal errors: %v", tt.name, diff, err)
		}
	}
}

type renderLSPTest struct {
	inLSP             *oc.Lsp
	inArgs            ISISRenderArgs
	wantNotifications []*gnmipb.Notification
	wantErrSubstring  string
}

var renderLSPTests = map[string]*renderLSPTest{
	"simple example": {
		inLSP: &oc.Lsp{
			Checksum:       ygot.Uint16(48899),
			LspId:          ygot.String("0000.4000.ce39.02-00"),
			SequenceNumber: ygot.Uint32(934033),
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
					ExtendedIsReachability: &oc.Lsp_Tlv_ExtendedIsReachability{
						Neighbor: map[string]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor{
							"0000.4000.ce39": {
								SystemId: ygot.String("0000.4000.ce39"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(0),
									},
								},
							},
						},
					},
				},
			},
		},
		inArgs: ISISRenderArgs{
			NetworkInstance:  "DEFAULT",
			ProtocolInstance: "15169",
			Level:            2,
			Timestamp:        time.Date(2017, time.April, 30, 8, 0, 0, 0, time.UTC),
		},
		wantNotifications: []*gnmipb.Notification{{
			Timestamp: 1493539200000000000,
			Prefix:    &gnmipb.Path{Element: []string{"network-instances", "network-instance", "DEFAULT", "protocols", "protocol", "ISIS", "15169", "isis", "levels", "level", "2", "link-state-database", "lsp", "0000.4000.ce39.02-00"}},
			Update: []*gnmipb.Update{{
				Path: &gnmipb.Path{Element: []string{"state", "checksum"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{48899}},
			}, {
				Path: &gnmipb.Path{Element: []string{"lsp-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39.02-00"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"state", "lsp-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39.02-00"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"state", "sequence-number"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{934033}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IS_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IS_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "system-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "state", "system-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "state", "id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}},
			Atomic: true,
		}},
	},
	"larger example": {
		inLSP: &oc.Lsp{
			Checksum:       ygot.Uint16(32515),
			LspId:          ygot.String("0000.4000.ce39.00-00"),
			SequenceNumber: ygot.Uint32(1320487),
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
					AreaAddress: &oc.Lsp_Tlv_AreaAddress{
						Address: []string{"39.752f.0100.0014.0000.9000.0001"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
					Ipv4TeRouterId: &oc.Lsp_Tlv_Ipv4TeRouterId{
						RouterId: []string{"10.244.168.31"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
					Ipv6Reachability: &oc.Lsp_Tlv_Ipv6Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_Ipv6Reachability_Prefix{
							"2607:f8b0::3:4000:ce39/128": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("2607:f8b0::3:4000:ce39/128"),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"2001:4860:c0a8:c920::/64": {
								Metric: ygot.Uint32(30),
								Prefix: ygot.String("2001:4860:c0a8:c920::/64"),
								SBit:   ygot.Bool(false),
								XBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
					Nlpid: &oc.Lsp_Tlv_Nlpid{
						Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV4,
							oc.OpenconfigIsis_Nlpid_Nlpid_IPV6,
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
					Capability: map[uint32]*oc.Lsp_Tlv_Capability{
						0: {
							InstanceNumber: ygot.Uint32(0),
							RouterId:       ygot.String("10.244.168.31"),
							Flags: []oc.E_OpenconfigIsis_Capability_Flags{
								oc.OpenconfigIsis_Capability_Flags_DOWN,
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
					Hostname: &oc.Lsp_Tlv_Hostname{
						Hostname: []string{"re0-pr05.sql88"},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
					ExtendedIpv4Reachability: &oc.Lsp_Tlv_ExtendedIpv4Reachability{
						Prefix: map[string]*oc.Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
							"10.244.168.31/32": {
								Metric: ygot.Uint32(0),
								Prefix: ygot.String("10.244.168.31/32"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
							"192.168.201.32/27": {
								Metric: ygot.Uint32(30),
								Prefix: ygot.String("192.168.201.32/27"),
								SBit:   ygot.Bool(false),
								UpDown: ygot.Bool(false),
							},
						},
					},
				},
				oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
					Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
					ExtendedIsReachability: &oc.Lsp_Tlv_ExtendedIsReachability{
						Neighbor: map[string]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor{
							"0000.4000.ce39": {
								SystemId: ygot.String("0000.4000.ce39"),
								Instance: map[uint64]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
									0: {
										Id:     ygot.Uint64(0),
										Metric: ygot.Uint32(30),
										Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
												Ipv4InterfaceAddress: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
													Address: []string{"192.168.201.35"},
												},
											},
											oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
												Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
												MaxReservableLinkBandwidth: &oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
													Bandwidth: float32ByteSlice(728.25),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inArgs: ISISRenderArgs{
			NetworkInstance:  "DEFAULT",
			ProtocolInstance: "15169",
			Level:            2,
			Timestamp:        time.Date(2017, time.May, 6, 14, 0, 0, 0, time.UTC),
		},
		wantNotifications: []*gnmipb.Notification{{
			Timestamp: 1494079200000000000,
			Prefix:    &gnmipb.Path{Element: []string{"network-instances", "network-instance", "DEFAULT", "protocols", "protocol", "ISIS", "15169", "isis", "levels", "level", "2", "link-state-database", "lsp", "0000.4000.ce39.00-00"}},
			Update: []*gnmipb.Update{{
				Path: &gnmipb.Path{Element: []string{"state", "lsp-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39.00-00"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"lsp-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39.00-00"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"state", "checksum"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{32515}},
			}, {
				Path: &gnmipb.Path{Element: []string{"state", "sequence-number"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{1320487}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "AREA_ADDRESSES", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"AREA_ADDRESSES"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "AREA_ADDRESSES", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"AREA_ADDRESSES"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "AREA_ADDRESSES", "area-address", "state", "address"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"39.752f.0100.0014.0000.9000.0001"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV4_TE_ROUTER_ID", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IPV4_TE_ROUTER_ID"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV4_TE_ROUTER_ID", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IPV4_TE_ROUTER_ID"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV4_TE_ROUTER_ID", "ipv4-te-router-id", "state", "router-id"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"10.244.168.31"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IPV6_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IPV6_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"2607:f8b0::3:4000:ce39/128"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "state", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"2607:f8b0::3:4000:ce39/128"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "state", "s-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "state", "x-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2607:f8b0::3:4000:ce39/128", "state", "up-down"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"2001:4860:c0a8:c920::/64"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "state", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"2001:4860:c0a8:c920::/64"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{30}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "state", "s-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "state", "x-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "IPV6_REACHABILITY", "ipv6-reachability", "prefixes", "prefix", "2001:4860:c0a8:c920::/64", "state", "up-down"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "NLPID", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"NLPID"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "NLPID", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"NLPID"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "NLPID", "nlpid", "state", "nlpid"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"IPV4"},
							}, {
								Value: &gnmipb.TypedValue_StringVal{"IPV6"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"ROUTER_CAPABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"ROUTER_CAPABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "router-capabilities", "capability", "0", "instance-number"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "router-capabilities", "capability", "0", "state", "instance-number"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "router-capabilities", "capability", "0", "state", "router-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"10.244.168.31"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "ROUTER_CAPABILITY", "router-capabilities", "capability", "0", "state", "flags"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"DOWN"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "DYNAMIC_NAME", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"DYNAMIC_NAME"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "DYNAMIC_NAME", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"DYNAMIC_NAME"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "DYNAMIC_NAME", "hostname", "state", "hostname"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"re0-pr05.sql88"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IPV4_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IPV4_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "10.244.168.31/32", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "10.244.168.31/32", "state", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"10.244.168.31/32"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "10.244.168.31/32", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"10.244.168.31/32"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "10.244.168.31/32", "state", "s-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "10.244.168.31/32", "state", "up-down"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "192.168.201.32/27", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{30}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "192.168.201.32/27", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"192.168.201.32/27"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "192.168.201.32/27", "state", "prefix"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"192.168.201.32/27"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "192.168.201.32/27", "state", "s-bit"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IPV4_REACHABILITY", "extended-ipv4-reachability", "prefixes", "prefix", "192.168.201.32/27", "state", "up-down"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{false}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IS_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"EXTENDED_IS_REACHABILITY"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "state", "system-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "system-id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"0000.4000.ce39"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "state", "id"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{0}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "state", "metric"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{30}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_IPV4_INTERFACE_ADDRESS", "ipv4-interface-address", "state", "address"}},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_LeaflistVal{
						&gnmipb.ScalarArray{
							Element: []*gnmipb.TypedValue{{
								Value: &gnmipb.TypedValue_StringVal{"192.168.201.35"},
							}},
						},
					},
				},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_IPV4_INTERFACE_ADDRESS", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IS_REACHABILITY_IPV4_INTERFACE_ADDRESS"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_IPV4_INTERFACE_ADDRESS", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IS_REACHABILITY_IPV4_INTERFACE_ADDRESS"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH", "state", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH", "type"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{"IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH"}},
			}, {
				Path: &gnmipb.Path{Element: []string{"tlvs", "tlv", "EXTENDED_IS_REACHABILITY", "extended-is-reachability", "neighbors", "neighbor", "0000.4000.ce39", "instances", "instance", "0", "subtlvs", "subtlv", "IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH", "max-reservable-link-bandwidth", "state", "bandwidth"}},
				Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BytesVal{[]byte{0x44, 0x36, 0x10, 0x00}}},
			}},
			Atomic: true,
		}},
	},
	"simple - pathelem path": {
		inLSP: func() *oc.Lsp {
			l := &oc.Lsp{}
			l.LspId = ygot.String("0000.4000.ce39.00-00")
			l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("0000.4000.ce39")
			return l
		}(),
		inArgs: ISISRenderArgs{
			NetworkInstance:  "DEFAULT",
			ProtocolInstance: "15169",
			Level:            2,
			Timestamp:        time.Date(2017, time.May, 6, 14, 0, 0, 0, time.UTC),
			UsePathElem:      true,
		},
		wantNotifications: []*gnmipb.Notification{{
			Timestamp: 1494079200000000000,
			Prefix:    mustPath("/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=ISIS][name=15169]/isis/levels/level[level-number=2]/link-state-database/lsp[lsp-id=0000.4000.ce39.00-00]"),
			Update: []*gnmipb.Update{{
				Path: mustPath("tlvs/tlv[type=EXTENDED_IS_REACHABILITY]/extended-is-reachability/neighbors/neighbor[system-id=0000.4000.ce39]/state/system-id"),
				Val:  mustTypedValue("0000.4000.ce39"),
			}, {
				Path: mustPath("tlvs/tlv[type=EXTENDED_IS_REACHABILITY]/extended-is-reachability/neighbors/neighbor[system-id=0000.4000.ce39]/system-id"),
				Val:  mustTypedValue("0000.4000.ce39"),
			}, {
				Path: mustPath("tlvs/tlv[type=EXTENDED_IS_REACHABILITY]/state/type"),
				Val:  mustTypedValue("EXTENDED_IS_REACHABILITY"),
			}, {
				Path: mustPath("tlvs/tlv[type=EXTENDED_IS_REACHABILITY]/type"),
				Val:  mustTypedValue("EXTENDED_IS_REACHABILITY"),
			}, {
				Path: mustPath("lsp-id"),
				Val:  mustTypedValue("0000.4000.ce39.00-00"),
			}, {
				Path: mustPath("state/lsp-id"),
				Val:  mustTypedValue("0000.4000.ce39.00-00"),
			}},
			Atomic: true,
		}},
	},
	"nil LSP ID": {
		inLSP:            &oc.Lsp{},
		wantErrSubstring: "nil LSP ID",
	},
	"nil LSP": {
		wantErrSubstring: "nil LSP",
	},
}

func TestRenderLSP(t *testing.T) {
	for name, tt := range renderLSPTests {
		got, err := RenderNotifications(tt.inLSP, tt.inArgs)
		if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
			t.Errorf("%s: RenderNotifications(%v, %v): got unexpected %s", name, tt.inLSP, tt.inArgs, diff)
		}

		if !testutil.NotificationSetEqual(got, tt.wantNotifications) {
			diff := pretty.Compare(got, tt.wantNotifications)
			t.Errorf("%s: RenderNotifications(%v, %v): got incorrect return protos, diff(-got,+want):\n%s", name, tt.inLSP, tt.inArgs, diff)
		}
	}
}

func benchmarkRenderLSP(b *testing.B, name string, usePathElem bool) {
	tt := *renderLSPTests[name]
	for i := 0; i != b.N; i++ {
		tt.inArgs.UsePathElem = usePathElem
		_, err := RenderNotifications(tt.inLSP, tt.inArgs)
		if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
			b.Errorf("%s: RenderNotifications(%v, %v): got unexpected %s", name, tt.inLSP, tt.inArgs, diff)
		}
	}
}

func BenchmarkRenderLSP(b *testing.B) {
	benchmarkTests := []string{"simple example", "larger example", "simple - pathelem path"}

	for _, usePathElem := range []bool{false, true} {
		for _, name := range benchmarkTests {
			b.Run(name+"/usePathElem="+strconv.FormatBool(usePathElem),
				func(b *testing.B) { benchmarkRenderLSP(b, name, usePathElem) })
		}
	}
}
