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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"

	"github.com/openconfig/lsdbparse/pkg/oc"
	"github.com/openconfig/ygot/ygot"
)

// binaryToUint32 takes an input byte slice, length 4, and parses it as a big
// endian uint32. Returns an error in the case that parsing fails, or the byte slice
// is not the correct length.
func binaryToUint32(n []byte) (uint32, error) {
	if len(n) != 4 {
		return 0, fmt.Errorf("input byte array was incorrect length: %d != 4", len(n))
	}

	var u uint32
	if err := binary.Read(bytes.NewBuffer(n), binary.BigEndian, &u); err != nil {
		return 0, err
	}

	return u, nil
}

// binaryToFloat32 takes an input byte slice, length 4, and parses it as a big
// endian float32. Returns an error in the case that parsing fails, or the byte slice
// is not the correct length.
func binaryToFloat32(n []byte) (float32, error) {
	u, err := binaryToUint32(n)
	if err != nil {
		return float32(0.0), err
	}

	return math.Float32frombits(u), nil
}

// ip4BytesToString takes a IPv4 address expressed as 4 bytes and returns it
// as a string representing an IPv4 address. Returns an error in the case that
// the address is the wrong length.
func ip4BytesToString(ip []byte) (string, error) {
	if len(ip) != 4 {
		return "", fmt.Errorf("ip4 addresses must be 32-bits")
	}
	return net.IP(ip).String(), nil
}

// ip6BytesToString takes an IPv6 address expressed as 16 bytes and returns it
// as a string representing an IPv6 address. Returns an error in the case that
// the address is the wrong length.
func ip6BytesToString(ip []byte) (string, error) {
	if len(ip) != 16 {
		return "", fmt.Errorf("ip6 addresses must be 128-bits")
	}
	return net.IP(ip).String(), nil
}

// getTLV retrieves a TLV from an isisLSP, creating it if it does not exist. Returns
// the TLV, a boolean indicating whether the TLV was created, or an error if one is
// experienced.
func (i *isisLSP) getTLV(t oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE) (*oc.Lsp_Tlv, bool, error) {
	tlv, ok := i.LSP.Tlv[t]
	var created bool
	if !ok {
		created = true
		var err error
		if tlv, err = i.LSP.NewTlv(t); err != nil {
			return nil, false, err
		}
	}
	return tlv, created, nil
}

// getTLVAndInit retrieves the specified type of TLV from an LSP, if the TLV
// does not exist within the LSP, it is created. The container within
// the TLV corresponding to the element containerName is initialised
// in the returned TLV.
func (i *isisLSP) getTLVAndInit(t oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE, containerName string) (*oc.Lsp_Tlv, error) {
	tlv, created, err := i.getTLV(t)
	if err != nil {
		return nil, err
	}

	if created {
		if err = ygot.InitContainer(tlv, containerName); err != nil {
			return nil, err
		}
	}

	return tlv, nil
}

// getCapabilitySubTLV retrieves the specified sub-TLV from the
// OpenConfig Router Capabilities TLV struct. If the sub-TLV does
// not exist, it is created.
func getCapabilitySubTLV(c *oc.Lsp_Tlv_Capability, t oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE) (*oc.Lsp_Tlv_Capability_Subtlv, error) {
	var stlv *oc.Lsp_Tlv_Capability_Subtlv
	stlv, ok := c.Subtlv[t]
	if !ok {
		var err error
		stlv, err = c.NewSubtlv(t)
		if err != nil {
			return nil, err
		}
	}
	return stlv, nil
}

// getExtendedISReachSubTLV retrieves the specified sub-TLV from the
// OpenConfig Extended IS Reachability TLV neighbour struct. If the
// sub-TLV does not exist, it is created, and the specified container
// initialised within it.
func getExtendedISReachSubTLV(n *oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance, t oc.E_OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE, c string) (*oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv, error) {
	var stlv *oc.Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv
	stlv, ok := n.Subtlv[t]
	if !ok {
		var err error
		stlv, err = n.NewSubtlv(t)
		if err != nil {
			return nil, err
		}
		if err = ygot.InitContainer(stlv, c); err != nil {
			return nil, err
		}
	}
	return stlv, nil
}

// canonicalHexString takes an input byte slice and returns it as a hexadecimal
// string in the canonical format for system IDs and LSP IDs - i.e.,
// xxxx.yyyy.zzzz for system IDs and xxxx.yyyy.zzzz.aa for LSP-IDs.
func canonicalHexString(in []byte) string {
	s := hex.EncodeToString(in)
	var b bytes.Buffer
	for i := 0; i <= len(s); i += 4 {
		e := i + 4
		if i+4 > len(s) {
			e = len(s)
		}
		b.WriteString(s[i:e])
		if e != len(s) {
			b.WriteString(".")
		}
	}
	return b.String()
}
