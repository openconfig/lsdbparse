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
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/lsdbparse/pkg/oc"
	"github.com/openconfig/ygot/ygot"
)

func TestTLVBytesToTLVs(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []*rawTLV
		wantErr bool
	}{{
		name: "single, simple TLV",
		in:   []byte{1, 2, 0, 0},
		want: []*rawTLV{
			{Type: 1, Length: 2, Value: []byte{0, 0}},
		},
	}, {
		name: "multiple TLVs",
		in:   []byte{1, 4, 0, 10, 20, 30, 2, 4, 0, 10, 20, 30},
		want: []*rawTLV{
			{Type: 1, Length: 4, Value: []byte{0, 10, 20, 30}},
			{Type: 2, Length: 4, Value: []byte{0, 10, 20, 30}},
		},
	}, {
		name:    "multiple TLVs, third TLV with no length specified",
		in:      []byte{1, 1, 10, 2, 1, 20, 3},
		wantErr: true,
	}, {
		name:    "multiple TLVs, third with a length greater than buffer length",
		in:      []byte{1, 1, 10, 2, 1, 20, 3, 42, 1},
		wantErr: true,
	}, {
		name:    "multiple TLVs, second with no content",
		in:      []byte{1, 1, 10, 2, 1},
		wantErr: true,
	}, {
		name: "multiple TLV, greater lengths",
		in: []byte{1, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			2, 10, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		want: []*rawTLV{
			{Type: 1, Length: 20, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
			{Type: 2, Length: 10, Value: []byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}},
		},
	}}

	for _, tt := range tests {
		got, err := TLVBytesToTLVs(tt.in)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: TLVBytesToTLVs(%v): got unexpected error: %v", tt.name, tt.in, err)
			}
			continue
		}

		if tt.wantErr {
			t.Errorf("%s: TLVBytesToTLVs(%v): did not get expected error", tt.name, tt.in)
			continue
		}

		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("%s: TLVBytesToTLVs(%v): did not get expected TLV set, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestProcessDynamicNameTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "hostname to new TLV",
		inTLV: &rawTLV{
			Value: []byte("pf01.cbf99"),
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
						Hostname: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Hostname{
							Hostname: []string{"pf01.cbf99"},
						},
					},
				},
			},
		},
	}, {
		name: "hostname to existing TLV",
		inTLV: &rawTLV{
			Value: []byte("bd07.sql88.net.google.com"),
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
						Hostname: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Hostname{
							Hostname: []string{"pf01.cbf99"},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
						Hostname: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Hostname{
							Hostname: []string{"pf01.cbf99", "bd07.sql88.net.google.com"},
						},
					},
				},
			},
		},
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processDynamicNameTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processDynamicNameTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processDynamicNameTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessAreaAddressTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "simple area address TLV",
		inTLV: &rawTLV{
			Value: []byte{0x1, 'a'},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
						AreaAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_AreaAddress{
							Address: []string{"61."},
						},
					},
				},
			},
		},
	}, {
		name: "area address with existing LSP",
		inTLV: &rawTLV{
			Value: []byte{0x2, 0x36, 0x24},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
						AreaAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_AreaAddress{
							Address: []string{"ffff"},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
						AreaAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_AreaAddress{
							Address: []string{"ffff", "36.24"},
						},
					},
				},
			},
		},
	}, {
		name: "area address overflow, first entry",
		inTLV: &rawTLV{
			Value: []byte{0x4, 0x1},
		},
		wantErr: true,
	}, {
		name: "area address overflow, subsequent entry",
		inTLV: &rawTLV{
			Value: []byte{0x1, 0x32, 0x42, 0xBE, 0xEF},
		},
		wantErr: true,
	}, {
		name: "area address with empty set of addresses",
		inTLV: &rawTLV{
			Value: []byte{},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
						Type:        oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
						AreaAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_AreaAddress{},
					},
				},
			},
		},
	}, {
		name: "area address with two addresses",
		inTLV: &rawTLV{
			Value: []byte{0x1, 0x1, 0x1, 0x2},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES: {
						Type:        oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES,
						AreaAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_AreaAddress{[]string{"01.", "02."}},
					},
				},
			},
		},
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processAreaAddressTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processAreaAddressTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processAreaAddressTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessProtocolsSupportedTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "simple nlpid TLV",
		inTLV: &rawTLV{
			Value: []byte{0xCC},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
						Nlpid: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Nlpid{
							Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{oc.OpenconfigIsis_Nlpid_Nlpid_IPV4},
						},
					},
				},
			},
		},
	}, {
		name: "nlpid TLV with existing LSP",
		inTLV: &rawTLV{
			Value: []byte{0x8E},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
						Nlpid: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Nlpid{
							Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{oc.OpenconfigIsis_Nlpid_Nlpid_IPV4},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID,
						Nlpid: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Nlpid{
							Nlpid: []oc.E_OpenconfigIsis_Nlpid_Nlpid{oc.OpenconfigIsis_Nlpid_Nlpid_IPV4, oc.OpenconfigIsis_Nlpid_Nlpid_IPV6},
						},
					},
				},
			},
		},
	}, {
		name: "nlpid with unknown value",
		inTLV: &rawTLV{
			Value: []byte{0x42},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processNLPIDTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processProtocolsSupportedTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processProtocolsSupportedTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessIPInterfaceAddressTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "simple IPv4 interface addresses TLV",
		inTLV: &rawTLV{
			Value: []byte{192, 168, 1, 2},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES,
						Ipv4InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4InterfaceAddresses{
							Address: []string{"192.168.1.2"},
						},
					},
				},
			},
		},
	}, {
		name: "IPv4 interface addresses TLV with existing LSP",
		inTLV: &rawTLV{
			Value: []byte{192, 168, 1, 2, 192, 0, 2, 1},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES,
						Ipv4InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4InterfaceAddresses{
							Address: []string{"10.0.0.1"},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES,
						Ipv4InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4InterfaceAddresses{
							Address: []string{"10.0.0.1", "192.168.1.2", "192.0.2.1"},
						},
					},
				},
			},
		},
	}, {
		name: "interface addresses with invalid length",
		inTLV: &rawTLV{
			Value: []byte{0x42},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processIPInterfaceAddressTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processIPInterfaceAddressTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processIPInterfaceAddressTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessIPv6InterfaceAddressTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "simple IPv6 interface addresses TLV",
		inTLV: &rawTLV{
			Value: []byte{0x20, 0x01, 0x4c, 0x20, 0x05, 0x06, 0x07, 0x08, 0x09, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x00},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES,
						Ipv6InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6InterfaceAddresses{
							Address: []string{"2001:4c20:506:708:90a:b0c:d0e:f00"},
						},
					},
				},
			},
		},
	}, {
		name: "IPv6 interface addresses TLV with existing LSP",
		inTLV: &rawTLV{
			Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x01, 0x0d, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xde, 0xad, 0xca, 0xfe},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES,
						Ipv6InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6InterfaceAddresses{
							Address: []string{"2001:db8::dead:beef"},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES,
						Ipv6InterfaceAddresses: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6InterfaceAddresses{
							Address: []string{"2001:db8::dead:beef", "2001:db8::", "2001:db8::dead:cafe"},
						},
					},
				},
			},
		},
	}, {
		name: "interface addresses with invalid length",
		inTLV: &rawTLV{
			Value: []byte{0x42, 0x47},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processIPv6InterfaceAddressTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processIPInterfaceAddressTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processIPInterfaceAddressTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessCapabilityTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "router capability TLV with no subTLVs",
		inTLV: &rawTLV{
			Value: []byte{192, 0, 2, 1, 0x3},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
						Capability: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability{
							0: {
								InstanceNumber: ygot.Uint32(0),
								RouterId:       ygot.String("192.0.2.1"),
								Flags: []oc.E_OpenconfigIsis_Capability_Flags{
									oc.OpenconfigIsis_Capability_Flags_DOWN,
									oc.OpenconfigIsis_Capability_Flags_FLOOD,
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "router capability TLV with only down not flood",
		inTLV: &rawTLV{
			Value: []byte{10, 0, 0, 1, 0x01},
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				i := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				c := i.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY).GetOrCreateCapability(0)
				c.InstanceNumber = ygot.Uint32(0)
				c.RouterId = ygot.String("10.0.0.1")
				c.Flags = []oc.E_OpenconfigIsis_Capability_Flags{
					oc.OpenconfigIsis_Capability_Flags_FLOOD,
				}
				return i
			}(),
		},
	}, {
		name: "invalid length subtlvs",
		inTLV: &rawTLV{
			Value: []byte{192, 0, 2, 1, 0x3, 42},
		},
		wantErr: true,
	}, {
		name: "invalid length router-id",
		inTLV: &rawTLV{
			Value: []byte{192, 42},
		},
		wantErr: true,
	}, {
		name: "router capability with unknown sub-TLV",
		inTLV: &rawTLV{
			Value: []byte{192, 0, 2, 1, 0x0, 42},
		},
		wantErr: true,
	}, {
		name: "router capability with SR algorithm sub-TLV",
		inTLV: &rawTLV{
			Value: []byte{
				// Router ID
				192, 0, 2, 1,
				// Flags
				0x0,
				// SubTLV type
				19,
				// SubTLV length
				2,
				// Algorithms
				0, 1,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
						Capability: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability{
							0: {
								InstanceNumber: ygot.Uint32(0),
								RouterId:       ygot.String("192.0.2.1"),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_ALGORITHM: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_ALGORITHM,
										SegmentRoutingAlgorithms: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingAlgorithms{
											Algorithm: []oc.E_OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm{
												oc.OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm_SPF,
												oc.OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm_STRICT_SPF,
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
	}, {
		name: "router capability with SR algorithm with overflow length",
		inTLV: &rawTLV{
			Value: []byte{192, 0, 2, 1, 0x0, 19, 42, 0},
		},
		wantErr: true,
	}, {
		name: "router capability with SR algorithm with unknown algorithm",
		inTLV: &rawTLV{
			Value: []byte{42, 42, 42, 42, 0x30, 19, 1, 42},
		},
		wantErr: true,
	}, {
		name: "router capability with SR capability",
		inTLV: &rawTLV{
			Value: []byte{
				// Router Capability TLV header
				84, 18, 192, 84, 0x0,
				// subTLV 2 == SR Capability
				2, 26,
				// Flags
				0xC0,
				// SR Capability sub-TLV
				// Range
				0x0, 0x0, 42,
				// SID/Label SubTLV
				1, 3, 0x0, 0x0, 42,
				// Range
				0x0, 0x0, 128,
				// SID/Label SubTLV
				1, 3, 0x0, 0x0, 128,
				// Range
				0x0, 0x0, 255,
				// SID/Label SubTLV
				1, 4, 0x0, 0x0, 0xFF, 0xFF,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY,
						Capability: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability{
							0: {
								InstanceNumber: ygot.Uint32(0),
								RouterId:       ygot.String("84.18.192.84"),
								Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv{
									oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_CAPABILITY: {
										Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_CAPABILITY,
										SegmentRoutingCapability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability{
											Flags: []oc.E_OpenconfigIsis_SegmentRoutingCapability_Flags{
												oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV4_MPLS,
												oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV6_MPLS,
											},
											SrgbDescriptor: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor{
												0: {Range: ygot.Uint32(42), Label: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor_Label_Union_Uint32{42}},
												1: {Range: ygot.Uint32(128), Label: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor_Label_Union_Uint32{128}},
												2: {Range: ygot.Uint32(255), Label: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor_Label_Union_Uint32{65535}},
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
	}, {
		name: "router capability with SR capability with invalid length",
		inTLV: &rawTLV{
			Value: []byte{84, 18, 192, 84, 0x0, 2, 128, 1, 1},
		},
		wantErr: true,
	}, {
		name: "router capability with SR capability with invalid SID/Label length",
		inTLV: &rawTLV{
			Value: []byte{84, 18, 192, 84, 0x0,
				2, 9,
				0xC0,
				0x0, 0x0, 0xFF,
				1, 42, 1, 2,
			},
		},
		wantErr: true,
	}, {
		name: "router capability with SR capability with invalid SID/Label type",
		inTLV: &rawTLV{
			Value: []byte{
				// Router Capability TLV header
				84, 18, 192, 84, 0x0,
				2, 9,
				0xC0,
				// SR Capability sub-TLV
				// Range
				0x0, 0x0, 42,
				// SID/Label SubTLV
				42, 3, 0x0, 0x0, 42,
			},
		},
		wantErr: true,
	}, {
		name: "router capability with SR capability with invalid SID/Label length for type",
		inTLV: &rawTLV{
			Value: []byte{
				84, 18, 192, 84, 0x0, 2, 10, 0xC0, 0x0, 0x0, 42,
				1, 4, 0x0, 0x0, 0x4,
			},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processCapabilityTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processCapabilityTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processCapabilityTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessIPv6ReachabilityTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "tlv with no subtlvs",
		inTLV: &rawTLV{
			Value: []byte{
				// Metric
				0x0, 0x0, 0x0, 0x2A,
				// Control Byte
				0xC0,
				// Prefix length
				0x3,
				// Octets of prefix - length of 3, means that we have 1 byte
				0x20,
				// No sub-TLVs
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2000::/3": {
									Prefix: ygot.String("2000::/3"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv with no subtlvs - updown and xbit unset",
		inTLV: &rawTLV{
			Value: []byte{
				// Metric
				0x0, 0x0, 0x0, 0x2A,
				// Control Byte
				0x00,
				// Prefix length
				0x3,
				// Octets of prefix - length of 3, means that we have 1 byte
				0x20,
				// No sub-TLVs
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2000::/3": {
									Prefix: ygot.String("2000::/3"),
									UpDown: ygot.Bool(false),
									XBit:   ygot.Bool(false),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv where address overflows",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC0,
				0x20, 0x3f, 0xfe,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with two prefixes",
		inTLV: &rawTLV{
			Value: []byte{
				// IPv6 Prefix 1.
				0x0, 0x0, 0x0, 0x2A,
				0xC0,
				0x10, 0x2f, 0xfe,
				// IPv6 Prefix 2.
				0x0, 0x0, 0x0, 0xA2,
				0xC0,
				0x3, 0x20,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2000::/3": {
									Prefix: ygot.String("2000::/3"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(162),
								},
								"2ffe::/16": {
									Prefix: ygot.String("2ffe::/16"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv with no subtlvs being appended to an existing LSP",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC0,
				0x10, 0x3f, 0xfe,
			},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2000::/3": {
									Prefix: ygot.String("2000::/3"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
							},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2000::/3": {
									Prefix: ygot.String("2000::/3"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
								"3ffe::/16": {
									Prefix: ygot.String("3ffe::/16"),
									UpDown: ygot.Bool(true),
									XBit:   ygot.Bool(true),
									SBit:   ygot.Bool(false),
									Metric: ygot.Uint32(42),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv with no subtlvs and invalid trailing data",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A, 0x80, 0x4,
				0x20, 0x42,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with no subtlvs, with subtlv present bit set",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x36, 0xE0, 0x4, 0x20,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with subtlvs, but insufficient data for length",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x36, 0xE0, 0x4, 0x20,
				// Length set to 16, but only 1 byte of subTLV
				0x10, 0x42,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with prefix SID subtlv, MPLS label encoding",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A, 0xE0, 0x20, 0x20, 0x01, 0x4c, 0x20,
				// Length of sub-TLVs
				0x7, 0x03, 0x5,
				// PrefixSID subTLV encoding, label value
				0xFC,
				// Algorithm
				0x00,
				// MPLS Label
				0x00, 0x00, 0xFF,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2001:4c20::/32": {
									Prefix: ygot.String("2001:4c20::/32"),
									UpDown: ygot.Bool(true),
									SBit:   ygot.Bool(true),
									XBit:   ygot.Bool(true),
									Metric: ygot.Uint32(42),
									Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv{
										oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
											Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
											PrefixSid: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv_PrefixSid{
												255: {
													Value:     ygot.Uint32(255),
													Algorithm: ygot.Uint8(0),
													Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
														oc.OpenconfigIsis_PrefixSid_Flags_READVERTISEMENT,
														oc.OpenconfigIsis_PrefixSid_Flags_NODE,
														oc.OpenconfigIsis_PrefixSid_Flags_NO_PHP,
														oc.OpenconfigIsis_PrefixSid_Flags_EXPLICIT_NULL,
														oc.OpenconfigIsis_PrefixSid_Flags_VALUE,
														oc.OpenconfigIsis_PrefixSid_Flags_LOCAL,
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
		},
	}, {
		name: "tlv with prefix SID subtlv, index value encoding",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A, 0xE0, 0x30, 0x20, 0x01, 0x4c, 0x20, 0x00, 0x42,
				// Length of sub-TLVs
				0x8, 0x03, 0x6,
				// PrefixSID subTLV encoding, index value
				0xF4,
				// Algorithm
				0x00,
				// index value
				0x00, 0x00, 0xFF, 0xFF,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY,
						Ipv6Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
								"2001:4c20:42::/48": {
									Prefix: ygot.String("2001:4c20:42::/48"),
									UpDown: ygot.Bool(true),
									SBit:   ygot.Bool(true),
									XBit:   ygot.Bool(true),
									Metric: ygot.Uint32(42),
									Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv{
										oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
											Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
											PrefixSid: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix_Subtlv_PrefixSid{
												uint32(0xFFFF): {
													Value:     ygot.Uint32(uint32(0xFFFF)),
													Algorithm: ygot.Uint8(0),
													Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
														oc.OpenconfigIsis_PrefixSid_Flags_READVERTISEMENT,
														oc.OpenconfigIsis_PrefixSid_Flags_NODE,
														oc.OpenconfigIsis_PrefixSid_Flags_NO_PHP,
														oc.OpenconfigIsis_PrefixSid_Flags_EXPLICIT_NULL,
														oc.OpenconfigIsis_PrefixSid_Flags_LOCAL,
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
		},
	}, {
		name: "tlv with prefix SID subtlv, value with incorrect length",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A, 0xE0, 0x30, 0x20, 0x01, 0x4c, 0x20, 0x00, 0x42,
				// Length of sub-TLVs
				0x8, 0x03, 0x6,
				// Prefix SID indicating 4-byte index
				0xF4,
				// Algorithm
				0x00,
				// Value with incorrect length
				0x00, 0x00, 0xFF,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with prefix SID subtlv, missing value bytes",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A, 0xE0, 0x30, 0x20, 0x01, 0x4c, 0x20, 0x00, 0x42,
				// Length of sub-TLVs
				0x4, 0x03, 0x2,
				// PrefixSID subTLV encoding, label value
				0xFC,
				// Algorithm
				0x00,
				// Missing bytes
			},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processIPv6ReachabilityTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processIPv6ReachabilityTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processIPv6ReachabiltyTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestIPv4TERouterIDTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "simple IPv4 TE Router ID",
		inTLV: &rawTLV{
			Value: []byte{192, 168, 1, 1},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
						Ipv4TeRouterId: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4TeRouterId{
							RouterId: []string{"192.168.1.1"},
						},
					},
				},
			},
		},
	}, {
		name: "short IPv4 TE Router ID TLV",
		inTLV: &rawTLV{
			Value: []byte{84, 18},
		},
		wantErr: true,
	}, {
		name: "long IPv4 TE Router ID TLV",
		inTLV: &rawTLV{
			Value: []byte{84, 18, 192, 72, 84},
		},
		wantErr: true,
	}, {
		name: "simple IPv4 TE Router ID",
		inTLV: &rawTLV{
			Value: []byte{84, 18, 192, 72},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
						Ipv4TeRouterId: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4TeRouterId{
							RouterId: []string{"192.16.1.1"},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID,
						Ipv4TeRouterId: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv4TeRouterId{
							RouterId: []string{"192.16.1.1", "84.18.192.72"},
						},
					},
				},
			},
		},
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processTERouterIDTLV(tt.inTLV)

		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processTERouterIDTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processTERouterIDTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessExtendedISReachabilityTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "short TLV",
		inTLV: &rawTLV{
			Value: []byte{0x10, 0x20},
		},
		wantErr: true,
	}, {
		name: "simple is-reachability tlv with zero subtlvs",
		inTLV: &rawTLV{
			Value: []byte{
				// System ID
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				// Default metric
				0, 0, 42,
				// SubTLV length
				0,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(42),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "append to existing neighbor in TLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				// Default metric
				0, 0, 42,
				// SubTLV length
				0x6,
				// SubTLV type
				0x3,
				// SubTLV len
				0x4,
				// SubTLV value
				0x0, 0x2A, 0x2A, 0x0,
			},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(42),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(42),
										},
										1: {
											Id:     ygot.Uint64(1),
											Metric: ygot.Uint32(42),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
													AdminGroup: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
														AdminGroup: []uint32{2763264},
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
		},
	}, {
		name: "is-reachability tlv with administrative group subtlv",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0x2A,
				// SubTLV length
				0x6,
				// SubTLV type
				0x3,
				// SubTLV len
				0x4,
				// SubTLV value
				0x0, 0x2A, 0x2A, 0x0,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(42),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP,
													AdminGroup: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdminGroup{
														AdminGroup: []uint32{2763264},
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
		},
	}, {
		name: "is-reachability TLV with incorrect length admin group",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0x2A,
				// Length of SubTLVs, SubTLV type and length
				0x6, 0x3, 0x3,
				// Value (should be 4b)
				0x2A, 0x2A,
			},
		},
		wantErr: true,
	}, {
		name: "is-reachability TLV with IPv4 Interface Address subTLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				// Length of SubTLVs
				0x6,
				// SubTLV type and length
				0x6, 0x4,
				// Value
				192, 168, 1, 1,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(255),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS,
													Ipv4InterfaceAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4InterfaceAddress{
														Address: []string{"192.168.1.1"},
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
		},
	}, {
		name: "is-reachability TLV with invalid length IPv4 Interface address",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				// Length of subTLVs
				0x5,
				// SubTLV type and length
				0x6, 0x3,
				// Value,
				10, 0, 1,
			},
		},
		wantErr: true,
	}, {
		name: "is-reachability TLV with IPv4 Neighbor Address subTLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				// Length of SubTLVs
				0x6,
				// SubTLV type and length
				0x8, 0x4,
				// Value
				192, 0, 2, 1,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(255),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS,
													Ipv4NeighborAddress: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_Ipv4NeighborAddress{
														Address: []string{"192.0.2.1"},
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
		},
	}, {
		name: "is-reachability TLV with IPv4 Neighbor Address with invalid length",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				0x7,
				0x8, 0x5,
				192, 168, 1, 2, 1,
			},
		},
		wantErr: true,
	}, {
		name: "is-reachability TLV with maximum link bandwidth sub-TLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				// Length of SubTLVs
				0x6,
				// SubTLV type and length
				0x9, 0x4,
				// 728.25 as a float32
				0x44, 0x36, 0x10, 0x00,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(255),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH,
													MaxLinkBandwidth: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxLinkBandwidth{
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
		},
	}, {
		name: "is-reachability TLV with maximum link bandwidth sub-TLV with invalid length",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				0x7,
				0x9, 0x5,
				0x44, 0x36, 0x10, 0x00, 0x10,
			},
		},
		wantErr: true,
	}, {
		name: "is-reachability TLV with maximum reservable bandwidth sub-TLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0xFF, 0xFF,
				// Length of SubTLVs
				06,
				// SubTLV type and length
				0xA, 0x4,
				// Value (728.25) as float 32
				0x44, 0x36, 0x10, 0x00,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(65535),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH,
													MaxReservableLinkBandwidth: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_MaxReservableLinkBandwidth{
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
		},
	}, {
		name: "is-reachability TLV with maximum reservable link bandwidth sub-TLV with invalid length",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				0x7,
				0x10, 0x3,
				0x44, 0x36, 0x10,
			},
		},
		wantErr: true,
	}, {
		name: "is-reachability TLV with residual bandwidth sub-TLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0xFF, 0xFF,
				// Length of SubTLVs
				06,
				// SubTLV type and length
				0x26, 0x4,
				// Value (728.25) as float 32
				0x44, 0x36, 0x10, 0x00,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY,
						ExtendedIsReachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability{
							Neighbor: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor{
								"4900.0000.0000.01": {
									SystemId: ygot.String("4900.0000.0000.01"),
									Instance: map[uint64]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance{
										0: {
											Id:     ygot.Uint64(0),
											Metric: ygot.Uint32(65535),
											Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv{
												oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_RESIDUAL_BANDWIDTH: {
													Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_RESIDUAL_BANDWIDTH,
													ResidualBandwidth: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_ResidualBandwidth{
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
		},
	}, {
		name: "is-reachability TLV with residual bandwidth sub-TLV with invalid length",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
				0x0, 0x0, 0xFF,
				0x9,
				0x10, 0x8,
				0x44, 0x36, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0,
			},
		},
		wantErr: true,
	}, {
		name: "short TLV after valid TLV",
		inTLV: &rawTLV{
			Value: []byte{
				0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x42, 0x0,
				0x42,
			},
		},
		wantErr: true,
	}, {
		name: "Unreserved bandwidth - valid values",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{34},
				// SubTLV type and length
				[]byte{0xB, 0x20},
				// Values per priority level
				float32ByteSlice(0.0),
				float32ByteSlice(1.0),
				float32ByteSlice(2.0),
				float32ByteSlice(3.0),
				float32ByteSlice(4.0),
				float32ByteSlice(5.0),
				float32ByteSlice(6.0),
				float32ByteSlice(7.0),
			),
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				l := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				neigh := l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("4900.0000.0000.01")
				n := neigh.GetOrCreateInstance(0)
				n.Metric = ygot.Uint32(65535)
				s := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH)
				for i := range []uint8{0, 1, 2, 3, 4, 5, 6, 7} {
					b := s.GetOrCreateSetupPriority(uint8(i))
					b.Bandwidth = float32ByteSlice(float32(i))
				}
				return l
			}(),
		},
	}, {
		name: "Unreserved bandwidth - invalid length",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{34},
				// SubTLV type and length
				[]byte{0x0, 0x0, 0x0},
			),
		},
		wantErr: true,
	}, {
		name: "link local and remote ID - invalid length",
		inTLV: &rawTLV{
			Length: 3,
		},
		wantErr: true,
	}, {
		name: "link local and remote ID",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{10},
				// SubTLV type and length
				[]byte{4, 8},
				// Local ID
				[]byte{0x1, 0x1, 0x1, 0x1},
				// Remote ID
				[]byte{0x2, 0x2, 0x2, 0x2},
			),
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				l := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				neigh := l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("4900.0000.0000.01")
				n := neigh.GetOrCreateInstance(0)
				n.Metric = ygot.Uint32(65535)
				s := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID).GetOrCreateLinkId()
				s.Local = ygot.Uint32(16843009)
				s.Remote = ygot.Uint32(33686018)
				return l
			}(),
		},
	}, {
		name: "link local and remote SID with invalid length",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{10},
				// SubTLV type and length
				[]byte{4, 7},
				// Local ID
				[]byte{0x1, 0x1, 0x1, 0x1},
				// Remote ID
				[]byte{0x2, 0x2, 0x2},
			),
		},
		wantErr: true,
	}, {
		name: "adjacency SID - valid value",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{7},
				// Type + Length
				[]byte{31, 5},
				// Flags and Value
				[]byte{0x30, 0xFF, 0x00, 0x00, 0x2A},
			),
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				l := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				neigh := l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("4900.0000.0000.01")
				n := neigh.GetOrCreateInstance(0)
				n.Metric = ygot.Uint32(65535)
				s := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID)
				if err := s.AppendAdjacencySid(&oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
					Value:  ygot.Uint32(42),
					Weight: ygot.Uint8(255),
					Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
						oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
						oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
					},
				}); err != nil {
					panic(err)
				}
				return l
			}(),
		},
	}, {
		name: "multiple adjacency SIDs",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{14},
				// Type and Length
				[]byte{31, 5},
				// Flags, Weight, and Value
				[]byte{0x30, 0xFF, 0x0, 0x0, 0x2A},
				// Type and Length
				[]byte{31, 5},
				// Flags, Weight, and Value
				[]byte{0x30, 0xFF, 0xFF, 0xFF, 0xFF},
			),
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				l := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				n := l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("4900.0000.0000.01").GetOrCreateInstance(0)
				n.Metric = ygot.Uint32(65535)
				s := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID)

				sids := []*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{{
					Value:  ygot.Uint32(42),
					Weight: ygot.Uint8(255),
					Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
						oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
						oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
					},
				}, {
					Value:  ygot.Uint32(16777215),
					Weight: ygot.Uint8(255),
					Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
						oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
						oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
					},
				}}

				for _, as := range sids {
					if err := s.AppendAdjacencySid(as); err != nil {
						panic(err)
					}
				}

				return l
			}(),
		},
	}, {
		name: "multiple LAN adjacency SIDs",
		inTLV: &rawTLV{
			Value: appendByteSlice(
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				[]byte{0x0, 0xFF, 0xFF},
				// Length of SubTLVs
				[]byte{26},
				// Type and Length
				[]byte{32, 11},
				// Flags, Weight
				[]byte{0x30, 0x00},
				// SystemID
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x2},
				// Value
				[]byte{0x0, 0x0, 0x1},
				// Type and Length
				[]byte{32, 11},
				// Flags, Weight
				[]byte{0x30, 0x0},
				// System ID
				[]byte{0x49, 0x0, 0x0, 0x0, 0x0, 0x03},
				// Value
				[]byte{0x0, 0x0, 0x2},
			),
		},
		wantLSP: &isisLSP{
			LSP: func() *oc.NetworkInstance_Protocol_Isis_Level_Lsp {
				l := &oc.NetworkInstance_Protocol_Isis_Level_Lsp{}
				n := l.GetOrCreateTlv(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY).GetOrCreateExtendedIsReachability().GetOrCreateNeighbor("4900.0000.0000.01").GetOrCreateInstance(0)
				n.Metric = ygot.Uint32(65535)
				s := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_LAN_SID)

				sids := []*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{{
					Value:      ygot.Uint32(1),
					Weight:     ygot.Uint8(0),
					NeighborId: ygot.String("4900.0000.0002"),
					Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
						oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
						oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
					},
				}, {
					Value:      ygot.Uint32(2),
					Weight:     ygot.Uint8(0),
					NeighborId: ygot.String("4900.0000.0003"),
					Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
						oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
						oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
					},
				}}

				for _, as := range sids {
					if err := s.AppendLanAdjacencySid(as); err != nil {
						panic(err)
					}
				}

				return l
			}(),
		},
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processExtendedISReachabilityTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processExtendedISReachabilityTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processExtendedISReachabilityTLV(%v): did not get expected LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func TestProcessExtendedIPv4ReachabilityTLV(t *testing.T) {
	tests := []struct {
		name    string
		inTLV   *rawTLV
		inLSP   *isisLSP
		wantLSP *isisLSP
		wantErr bool
	}{{
		name: "tlv with no subtlvs",
		inTLV: &rawTLV{
			Value: []byte{
				// Metric
				0x0, 0x0, 0x0, 0x2A,
				// Control - 0b10100000 = up/down, 32 bit prefix
				0xA0,
				// 4-bytes of prefix
				192, 168, 1, 1,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.168.1.1/32": {
									Prefix: ygot.String("192.168.1.1/32"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
							},
						},
					},
				},
			},
		},
	}, {

		name: "tlv with two prefixes with no subtlvs",
		inTLV: &rawTLV{
			Value: []byte{
				// Metric
				0x0, 0x0, 0x0, 0x2A,
				// Control - 0b10100000 = up/down, 32 bit prefix
				0xA0,
				// 4-bytes of prefix
				192, 168, 1, 1,
				// Metric
				0x0, 0x0, 0x0, 0xFF,
				// Control
				0xA0,
				// 4 bytes of prefix
				192, 0, 2, 1,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.168.1.1/32": {
									Prefix: ygot.String("192.168.1.1/32"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
								"192.0.2.1/32": {
									Prefix: ygot.String("192.0.2.1/32"),
									Metric: ygot.Uint32(255),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv where prefix length is >32",
		inTLV: &rawTLV{
			Value: []byte{
				// Metric
				0x0, 0x0, 0x0, 0x2A,
				// Control - 0b00111111 pfx len == 63
				0x3F,
				// 9 bytes of prefix (63+7)/8
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			},
		},
		wantErr: true,
	}, {
		name: "tlv where address overflows",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xA0,
				192, 168, 1, 1, 1,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with no subtlvs being appended to an existing LSP",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x2A, 0x2A,
				// up/down set, length 8 prefix
				0x88,
				// prefix
				0xA,
				// No subTLVs.
			},
		},
		inLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.168.1.1/32": {
									Prefix: ygot.String("192.168.1.1/32"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
							},
						},
					},
				},
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.168.1.1/32": {
									Prefix: ygot.String("192.168.1.1/32"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
								"10.0.0.0/8": {
									Prefix: ygot.String("10.0.0.0/8"),
									Metric: ygot.Uint32(10794),
									SBit:   ygot.Bool(false),
									UpDown: ygot.Bool(true),
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "tlv with no subtlvs, with subtlv present bit set",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				// subTLV present bit set, pfx len 8
				0xC4,
				192,
				// Missing subTLVs.
			},
		},
		wantErr: true,
	}, {
		name: "tlv with subtlvs, but insufficient data for length",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC4,
				192,
				// SubTLV length
				0x2A,
				// SubTLV contents
				0x42, 0x42, 0x42,
			},
		},
		wantErr: true,
	}, {
		name: "tlv with prefix SID subtlv, MPLS label encoding",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC4,
				192,
				// SubTLV length
				0x7,
				// SubTLV contents
				0x3, 0x5,
				// PrefixSID flags, 0b11110111 - such that all flags are set.
				0xFC,
				// Algorithm
				0x1,
				// MPLS label value
				0x0, 0x0, 0x2A,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.0.0.0/4": {
									Prefix: ygot.String("192.0.0.0/4"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(true),
									UpDown: ygot.Bool(true),
									Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv{
										oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
											Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
											PrefixSid: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv_PrefixSid{
												42: {
													Algorithm: ygot.Uint8(1),
													Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
														oc.OpenconfigIsis_PrefixSid_Flags_READVERTISEMENT,
														oc.OpenconfigIsis_PrefixSid_Flags_NODE,
														oc.OpenconfigIsis_PrefixSid_Flags_NO_PHP,
														oc.OpenconfigIsis_PrefixSid_Flags_EXPLICIT_NULL,
														oc.OpenconfigIsis_PrefixSid_Flags_VALUE,
														oc.OpenconfigIsis_PrefixSid_Flags_LOCAL,
													},
													Value: ygot.Uint32(42),
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
	}, {
		name: "tlv with prefix SID subtlv, index value encoding",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC4,
				192,
				// SubTLV length
				0x8,
				// SubTLV contents
				0x3, 0x6,
				// Prefix SID flags, value and local unset.
				0xF4,
				// Algorithm
				0x0,
				// Index value
				0x2A, 0x2A, 0x2A, 0x2A,
			},
		},
		wantLSP: &isisLSP{
			LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY,
						ExtendedIpv4Reachability: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability{
							Prefix: map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
								"192.0.0.0/4": {
									Prefix: ygot.String("192.0.0.0/4"),
									Metric: ygot.Uint32(42),
									SBit:   ygot.Bool(true),
									UpDown: ygot.Bool(true),
									Subtlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv{
										oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID: {
											Type: oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID,
											PrefixSid: map[uint32]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix_Subtlv_PrefixSid{
												707406378: {
													Algorithm: ygot.Uint8(0),
													Flags: []oc.E_OpenconfigIsis_PrefixSid_Flags{
														oc.OpenconfigIsis_PrefixSid_Flags_READVERTISEMENT,
														oc.OpenconfigIsis_PrefixSid_Flags_NODE,
														oc.OpenconfigIsis_PrefixSid_Flags_NO_PHP,
														oc.OpenconfigIsis_PrefixSid_Flags_EXPLICIT_NULL,
														oc.OpenconfigIsis_PrefixSid_Flags_LOCAL,
													},
													Value: ygot.Uint32(707406378),
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
	}, {
		name: "tlv with prefix SID subtlv, value with incorrect length",
		inTLV: &rawTLV{
			Value: []byte{
				0x0, 0x0, 0x0, 0x2A,
				0xC4,
				192,
				// SubTLV length
				0x9,
				// SubTLV contents
				0x3, 0x5,
				//  MPLS label specified
				0xF7,
				// Algorithm
				0x0,
				// Index value
				0x2A, 0x2A, 0x2A, 0x2A,
			},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		got := tt.inLSP
		if got == nil {
			got = newISISLSP()
		}

		err := got.processExtendedIPReachTLV(tt.inTLV)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: i.processExtendedIPReachTLV(%v): got unexpected error: %v", tt.name, tt.inTLV, err)
			}
			continue
		}

		if diff := pretty.Compare(got, tt.wantLSP); diff != "" {
			t.Errorf("%s: i.processExtendedIPReachTLV(%v): got incorrect LSP, diff(-got,+want):\n%s", tt.name, tt.inTLV, diff)
		}
	}
}

func appendByteSlice(bs ...[]byte) []byte {
	cs := []byte{}
	for _, b := range bs {
		cs = append(cs, b...)
	}
	return cs
}

func TestParseUnreservedBandwidthSubTLV(t *testing.T) {
	tests := []struct {
		name             string
		inTLV            *rawTLV
		want             map[uint8][]byte
		wantErrSubstring string
	}{{
		name: "incorrect length",
		inTLV: &rawTLV{
			Length: 12,
		},
		wantErrSubstring: "invalid length",
	}, {
		name: "correct length but incorrect payload length",
		inTLV: &rawTLV{
			Length: 32,
			Value: []byte{
				0x0, 0x0, 0x0,
			},
		},
		wantErrSubstring: "invalid length",
	}, {
		name: "valid sub-TLV",
		inTLV: &rawTLV{
			Length: 32,
			Value: appendByteSlice(
				float32ByteSlice(400.25),                // 0
				float32ByteSlice(800.96),                // 1
				float32ByteSlice(1024.84),               // 2
				float32ByteSlice(90283.92),              // 3
				float32ByteSlice(1024935.92),            // 4
				float32ByteSlice(1010124124.84),         // 5
				float32ByteSlice(191291242145.81292),    // 6
				float32ByteSlice(1919124128582.2810424), // 7
			),
		},
		want: map[uint8][]byte{
			0: float32ByteSlice(400.25),
			1: float32ByteSlice(800.96),
			2: float32ByteSlice(1024.84),
			3: float32ByteSlice(90283.92),
			4: float32ByteSlice(1024935.92),
			5: float32ByteSlice(1010124124.84),
			6: float32ByteSlice(191291242145.81292),
			7: float32ByteSlice(1919124128582.2810424),
		},
	}}

	for _, tt := range tests {
		got, err := parseUnreservedBandwidthSubTLV(tt.inTLV)
		if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
			t.Errorf("%s: parseUnreservedBandwidthSubTLV(%v): did not get expected error, %s", tt.name, tt.inTLV, diff)
		}

		if err != nil {
			continue
		}

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: parseUnreservedBandwidthSubTLV(%v): did not get expected result, got: %v, want: %v", tt.name, tt.inTLV, got, tt.want)
		}
	}
}

func TestParseAdjSIDSubTLV(t *testing.T) {
	tests := []struct {
		name             string
		in               *rawTLV
		want             *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid
		wantErrSubstring string
	}{{
		name: "invalid length",
		in: &rawTLV{
			Value: []byte{0x00},
		},
		wantErrSubstring: "invalid length for adjacency SID",
	}, {
		name: "address family flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 7 set
				0x80,
				// Weight
				0x00,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY,
			},
			Value:  ygot.Uint32(0),
			Weight: ygot.Uint8(0),
		},
	}, {
		name: "backup flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 6 set
				0x40,
				// Weight
				0x0,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_BACKUP,
			},
			Value:  ygot.Uint32(0),
			Weight: ygot.Uint8(0),
		},
	}, {
		name: "local and value flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 2 and 3 set.
				0x30,
				// Weight
				0x00,
				// Label value
				0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
				oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
			},
			Value:  ygot.Uint32(0),
			Weight: ygot.Uint8(0),
		},
	}, {

		name: "set flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 4 set
				0x8,
				// Weight
				0x00,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_SET,
			},
			Value:  ygot.Uint32(0),
			Weight: ygot.Uint8(0),
		},
	}, {
		name: "label value with weight",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0xF0,
				// Weight
				0xFF,
				// Value (local + value set - label)
				0x10, 0x10, 0x10,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY,
				oc.OpenconfigIsis_AdjacencySid_Flags_BACKUP,
				oc.OpenconfigIsis_AdjacencySid_Flags_VALUE,
				oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL,
			},
			Weight: ygot.Uint8(255),
			Value:  ygot.Uint32(1052688),
		},
	}, {
		name: "label value with incorrect length",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0xF0,
				// Weight
				0xFF,
				// Value len should be 3.
				0x10, 0x10, 0x10, 0x10,
			},
		},
		wantErrSubstring: "invalid length for adjacency SID containing label",
	}, {
		name: "value with weight",
		in: &rawTLV{
			Value: []byte{
				// Bits 4 and 5 set
				0xC,
				// Weight
				0xF,
				// Value - 4 bytes.
				0x00, 0x00, 0x00, 0x2A,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
			Flags: []oc.E_OpenconfigIsis_AdjacencySid_Flags{
				oc.OpenconfigIsis_AdjacencySid_Flags_SET,
				// TODO(robjs): Add persistent
			},
			Weight: ygot.Uint8(15),
			Value:  ygot.Uint32(42),
		},
	}, {
		name: "index value with incorrect length",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0x0,
				// Weight
				0xFF,
				// Value length should be 4
				0x10, 0x10, 0x10, 0x10, 0x10,
			},
		},
		wantErrSubstring: "invalid length for adjacency SID containing index",
	}, {
		name: "short TLV",
		in: &rawTLV{
			Value: []byte{0x2A},
		},
		wantErrSubstring: "invalid length for adjacency SID",
	}, {
		name: "wrong combination of value and local",
		in: &rawTLV{
			Value: []byte{
				// Value bit only set
				0x20,
				// Weight
				0xFF,
				// Contents does not matter
				0x00, 0x00, 0x00, 0x00,
			},
		},
		wantErrSubstring: "invalid combination of value and local",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAdjSIDSubTLV(tt.in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("parseAdjSIDSubTLV(%v): did not get expected error, %s", tt.in, diff)
			}

			if err != nil {
				return
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("parseAdjSIDSubTLV(%v): did not get expected output, diff(+got,-want):\n%s", tt.in, diff)
			}
		})
	}
}

func TestParseLANAdjSIDSubTLV(t *testing.T) {
	tests := []struct {
		name             string
		in               *rawTLV
		want             *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid
		wantErrSubstring string
	}{{
		name: "invalid length",
		in: &rawTLV{
			Value: []byte{0x00},
		},
		wantErrSubstring: "invalid length for LAN AdjSID",
	}, {
		name: "address family flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 7 set
				0x80,
				// Weight
				0x00,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_ADDRESS_FAMILY,
			},
			Value:      ygot.Uint32(0),
			Weight:     ygot.Uint8(0),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {
		name: "backup flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 6 set
				0x40,
				// Weight
				0x0,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_BACKUP,
			},
			Value:      ygot.Uint32(0),
			Weight:     ygot.Uint8(0),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {
		name: "local and value flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 2 and 3 set.
				0x30,
				// Weight
				0x00,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Label value
				0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
				oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
			},
			Value:      ygot.Uint32(0),
			Weight:     ygot.Uint8(0),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {

		name: "set flag",
		in: &rawTLV{
			Value: []byte{
				// Bit 4 set
				0x8,
				// Weight
				0x00,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value
				0x00, 0x00, 0x00, 0x00,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_SET,
			},
			Value:      ygot.Uint32(0),
			Weight:     ygot.Uint8(0),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {
		name: "label value with weight",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0xF0,
				// Weight
				0xFF,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value (local + value set - label)
				0x10, 0x10, 0x10,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_ADDRESS_FAMILY,
				oc.OpenconfigIsis_LanAdjacencySid_Flags_BACKUP,
				oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE,
				oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL,
			},
			Weight:     ygot.Uint8(255),
			Value:      ygot.Uint32(1052688),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {
		name: "label value with incorrect length",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0xF0,
				// Weight
				0xFF,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value len should be 3.
				0x10, 0x10, 0x10, 0x10,
			},
		},
		wantErrSubstring: "invalid length for adjacency SID containing label",
	}, {
		name: "value with weight",
		in: &rawTLV{
			Value: []byte{
				// Bits 4 and 5 set
				0xC,
				// Weight
				0xF,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value - 4 bytes.
				0x00, 0x00, 0x00, 0x2A,
			},
		},
		want: &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
			Flags: []oc.E_OpenconfigIsis_LanAdjacencySid_Flags{
				oc.OpenconfigIsis_LanAdjacencySid_Flags_SET,
				// TODO(robjs): Add persistent
			},
			Weight:     ygot.Uint8(15),
			Value:      ygot.Uint32(42),
			NeighborId: ygot.String("4900.0000.0001"),
		},
	}, {
		name: "index value with incorrect length",
		in: &rawTLV{
			Value: []byte{
				// Bits 0-3 set.
				0x0,
				// Weight
				0xFF,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Value length should be 4
				0x10, 0x10, 0x10, 0x10, 0x10,
			},
		},
		wantErrSubstring: "invalid length for adjacency SID containing index",
	}, {
		name: "short TLV",
		in: &rawTLV{
			Value: []byte{0x2A},
		},
		wantErrSubstring: "invalid length for LAN AdjSID",
	}, {
		name: "wrong combination of value and local",
		in: &rawTLV{
			Value: []byte{
				// Value bit only set
				0x20,
				// Weight
				0xFF,
				// System ID
				0x49, 0, 0, 0, 0, 1,
				// Contents does not matter
				0x00, 0x00, 0x00, 0x00,
			},
		},
		wantErrSubstring: "invalid combination of value and local",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLANAdjSIDSubTLV(tt.in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("parseAdjSIDSubTLV(%v): did not get expected error, %s", tt.in, diff)
			}

			if err != nil {
				return
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("parseAdjSIDSubTLV(%v): did not get expected output, diff(+got,-want):\n%s", tt.in, diff)
			}
		})
	}
}

func TestParseLSPFlags(t *testing.T) {
	tests := []struct {
		name string
		in   uint8
		want []oc.E_OpenconfigIsis_Lsp_Flags
	}{{
		name: "partition repair",
		in:   0x80,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_PARTITION_REPAIR},
	}, {
		name: "attached error",
		in:   0x40,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_ATTACHED_ERROR},
	}, {
		name: "attached expense",
		in:   0x20,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_ATTACHED_EXPENSE},
	}, {
		name: "attached delay",
		in:   0x10,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_ATTACHED_DELAY},
	}, {
		name: "attached default",
		in:   0x8,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_ATTACHED_DEFAULT},
	}, {
		name: "overload",
		in:   0x4,
		want: []oc.E_OpenconfigIsis_Lsp_Flags{oc.OpenconfigIsis_Lsp_Flags_OVERLOAD},
	}}

	for _, tt := range tests {
		if got := parseLSPFlags(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: parseLSPFlags(%d): did not get expected output, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestParseLinkLocalRemoteSubTLV(t *testing.T) {
	tests := []struct {
		name             string
		in               *rawTLV
		wantLocal        uint32
		wantRemote       uint32
		wantErrSubstring string
	}{{
		name: "length too short - length field",
		in: &rawTLV{
			Length: 4,
			Value:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		wantErrSubstring: "invalid length for link local/remote identifier sub-TLV",
	}, {
		name: "length too short - value field",
		in: &rawTLV{
			Length: 8,
			Value:  []byte{0},
		},
		wantErrSubstring: "invalid length for link local/remote identifier sub-TLV",
	}, {
		name: "valid subTLV",
		in: &rawTLV{
			Length: 8,
			Value:  []byte{0, 0, 0, 42, 0, 0, 0, 84},
		},
		wantLocal:  42,
		wantRemote: 84,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLocal, gotRemote, err := parseLinkLocalRemoteSubTLV(tt.in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if got, want := gotLocal, tt.wantLocal; got != want {
				t.Errorf("did not get expected local value, got: %d, want: %d", got, want)
			}

			if got, want := gotRemote, tt.wantRemote; got != want {
				t.Errorf("did not get expected remote value, got: %d, want: %d", got, want)
			}
		})
	}
}
