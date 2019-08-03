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
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/lsdbparse/pkg/oc"
)

func TestBinaryToUint32(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint32
		wantErr bool
	}{{
		name: "value using single least significant byte",
		in:   []byte{0, 0, 0, 1},
		want: 1,
	}, {
		name: "value using most significant byte",
		in:   []byte{1, 0, 0, 0},
		want: 16777216,
	}, {
		name:    "short incorrect length",
		in:      []byte{1, 2},
		wantErr: true,
	}, {
		name:    "long incorrect length",
		in:      []byte{1, 2, 3, 4, 5},
		wantErr: true,
	}}

	for _, tt := range tests {
		got, err := binaryToUint32(tt.in)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: binaryToUint32(%v): got unexpected error: %v", tt.name, tt.in, err)
			}
			continue
		}

		if tt.wantErr {
			t.Errorf("%s: binaryToUint32(%v): did not get expected error", tt.name, tt.in)
		}

		if got != tt.want {
			t.Errorf("%s: binaryToUint32(%v): did not get expected value, got: %d, want: %d", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestBinaryToFloat32(t *testing.T) {
	// The encoding for a float32 is:
	// 1-bit sign
	// 8-bit exponent
	// 23-bit fraction
	tests := []struct {
		name    string
		in      []byte
		want    float32
		wantErr bool
	}{{
		name: "positive float32 value",
		in:   []byte{0x44, 0x36, 0x10, 0x00},
		want: float32(728.25),
	}, {
		name: "negative float32 value",
		in:   []byte{0xC4, 0x1, 0x4F, 0x00},
		want: float32(-517.2344),
	}, {
		name:    "float32, too short",
		in:      []byte{0x00, 0x10},
		wantErr: true,
	}, {
		name:    "float32, too long",
		in:      []byte{0x00, 0x24, 0x32, 0x96, 0x8F},
		wantErr: true,
	}}

	for _, tt := range tests {
		got, err := binaryToFloat32(tt.in)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: binaryToFloat32(%v): got unexpected error: %v", tt.name, tt.in, err)
			}
			continue
		}

		if tt.wantErr {
			t.Errorf("%s: binaryToFloat32(%v): did not get expected error", tt.name, tt.in)
		}

		if got != tt.want {
			t.Errorf("%s: binaryToFloat32(%v): did got get expected value, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestIP4BytesToString(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{{
		name: "ip4 rfc1918 address",
		in:   []byte{10, 192, 64, 32},
		want: "10.192.64.32",
	}, {
		name: "ip4 non-rfc1918 addresS",
		in:   []byte{84, 18, 192, 64},
		want: "84.18.192.64",
	}, {
		name:    "ip4, too short",
		in:      []byte{84},
		wantErr: true,
	}, {
		name:    "ip4, too long",
		in:      []byte{42, 42, 42, 42, 42},
		wantErr: true,
	}}

	for _, tt := range tests {
		got, err := ip4BytesToString(tt.in)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: ip4BytesToString(%v): got unexpected error: %v", tt.name, tt.in, err)
			}
			continue
		}

		if tt.wantErr {
			t.Errorf("%s: ip4BytesToString(%v): did not get expected error", tt.name, tt.in)
		}

		if got != tt.want {
			t.Errorf("%s: ip4BytesToString(%v): did not get expected value, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestIP6BytesToString(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{{
		name: "ipv6 all octets",
		in:   []byte{0x20, 0x01, 0x42, 0x00, 0x32, 0x21, 0x00, 0x01, 0x00, 0x20, 0x42, 0x21, 0x1F, 0xA, 0x1F, 0xFF},
		want: "2001:4200:3221:1:20:4221:1f0a:1fff",
	}, {
		name: "ipv6, compression",
		in:   []byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		want: "2001::1",
	}, {
		name:    "invalid length, short",
		in:      []byte{0x00, 0x00},
		wantErr: true,
	}, {
		name:    "invalid length, long",
		in:      []byte{0x20, 0x01, 0x00, 0x12, 0x13, 0x14, 0x42, 0x52, 0xFF, 0x0A, 0xA, 0xBF, 0x42, 0x96, 0xFA, 0xAA, 0x42, 0xAB},
		wantErr: true,
	}}

	for _, tt := range tests {
		got, err := ip6BytesToString(tt.in)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: ip6BytesToString(%v): got unexpected error: %v", tt.name, tt.in, err)
			}
			continue
		}

		if tt.wantErr {
			t.Errorf("%s: ip6BytesToString(%v): did not get expected error", tt.name, tt.in)
		}

		if got != tt.want {
			t.Errorf("%s: ip6BytesToString(%v): did not get expected value, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestGetTLV(t *testing.T) {
	// Tests existingTLVOrNew also.
	tests := []struct {
		name               string
		inTLVName          oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE
		inTLVContainerName string
		inLSP              *isisLSP
		wantTLV            *oc.Lsp_Tlv
	}{{
		name:               "new tlv",
		inTLVName:          oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
		inTLVContainerName: "Hostname",
		wantTLV: &oc.Lsp_Tlv{
			Type:     oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
			Hostname: &oc.Lsp_Tlv_Hostname{},
		},
	}, {
		name:               "existing TLV",
		inTLVName:          oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
		inTLVContainerName: "Hostname",
		inLSP: &isisLSP{
			LSP: &oc.Lsp{
				Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.Lsp_Tlv{
					oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME: {
						Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
						Hostname: &oc.Lsp_Tlv_Hostname{
							Hostname: []string{"fish"},
						},
					},
				},
			},
		},
		wantTLV: &oc.Lsp_Tlv{
			Type: oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME,
			Hostname: &oc.Lsp_Tlv_Hostname{
				Hostname: []string{"fish"},
			},
		},
	}}

	for _, tt := range tests {
		i := tt.inLSP
		if i == nil {
			i = newISISLSP()
		}

		got, err := i.getTLVAndInit(tt.inTLVName, tt.inTLVContainerName)
		if err != nil {
			t.Errorf("%s: i.getTLVAndInit(%v, %v): got unexpected error: %v", tt.name, tt.inTLVName, tt.inTLVContainerName, err)
		}

		if diff := pretty.Compare(got, tt.wantTLV); diff != "" {
			t.Errorf("%s: i.getTLVAndInit(%v, %v): did not get expected TLV, diff(-got,+want):%s\n", tt.name, tt.inTLVName, tt.inTLVContainerName, diff)
		}
	}
}

func TestCanonicalHexString(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{{
		name: "simple system ID",
		in:   []byte{192, 168, 2, 117, 42, 84},
		want: "c0a8.0275.2a54",
	}, {
		name: "simple LSP ID",
		in:   []byte{10, 0, 0, 8, 0, 0, 42},
		want: "0a00.0008.0000.2a",
	}, {
		name: "short",
		in:   []byte{0x42},
		want: "42",
	}}

	for _, tt := range tests {
		if got := canonicalHexString(tt.in); got != tt.want {
			t.Errorf("%s: canonicalHexString(%v): did not get expected formatted system ID, got: %v, want: %v", tt.name, tt.in, got, tt.want)
		}
	}
}
