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
	"errors"
	"fmt"

	"github.com/openconfig/gnmi/errlist"
	"github.com/openconfig/lsdbparse/pkg/oc"
	"github.com/openconfig/ygot/ygot"
)

const (
	// Names of the containers that are used within the OpenConfig
	// YANG schema for each TLV.
	dynamicNameContainer              string = "Hostname"
	areaAddressContainer              string = "AreaAddress"
	ipv4InterfaceAddressContainer     string = "Ipv4InterfaceAddresses"
	nlpidContainer                    string = "Nlpid"
	ipv6InterfaceAddressContainer     string = "Ipv6InterfaceAddresses"
	routerCapabilityContainer         string = "Capability"
	ipv6ReachabilityContainer         string = "Ipv6Reachability"
	ipv4TERouterIDContainer           string = "Ipv4TeRouterId"
	ipv4InterfaceAddressesContainer   string = "Ipv4InterfaceAddresses"
	ipv6InterfaceAddressesContainer   string = "Ipv6InterfaceAddresses"
	extendedISReachabilityContainer   string = "ExtendedIsReachability"
	extendedIPv4ReachabilityContainer string = "ExtendedIpv4Reachability"
	// Names of the containers that are used within the Extended IS
	// Reachability SubTLV structure.
	extISReachAdminGroupContainer  string = "AdminGroup"
	extISReachAvailableBandwidth   string = "AvailableBandwidth"
	extISReachIPv4InterfaceAddress string = "Ipv4InterfaceAddress"
	extISReachIPv4NeighborAddress  string = "Ipv4NeighborAddress"
	extISReachMaxLinkBW            string = "MaxLinkBandwidth"
	extISReachMaxReservableBW      string = "MaxReservableLinkBandwidth"
	extISReachResidualBW           string = "ResidualBandwidth"
)

const (
	// Constants for bit positions that are used for comparison
	// of flags.
	bit0 uint8 = 0x80
	bit1 uint8 = 0x40
	bit2 uint8 = 0x20
	bit3 uint8 = 0x10
	bit4 uint8 = 0x8
	bit5 uint8 = 0x4
	bit6 uint8 = 0x2
	bit7 uint8 = 0x1
)

// TLVBytesToTLVs takes an input byte slice that contains the TLVs section
// of the LSP, and extracts the TLVs as a slice of structs. Returns an error if
// unable to extract the TLVs.
func TLVBytesToTLVs(tlvBytes []byte) ([]*rawTLV, error) {
	var tlvs []*rawTLV
	var tlvLen int
	// Update the position within the tlvBytes slice, 2 bytes of type and length,
	// and then the specified number of bytes for the length.
	for pos := 0; pos < len(tlvBytes); pos += 2 + tlvLen {
		if pos == len(tlvBytes)-1 {
			return nil, fmt.Errorf("invalid length of TLVs, got a TLV with type and no length: %d", pos)
		}

		tlvLen = int(tlvBytes[pos+1])
		if pos+2+tlvLen > len(tlvBytes) {
			return nil, fmt.Errorf("invalid length of TLVs, overflowed buffer, at: %d, length: %d", pos+2, tlvLen)
		}

		var tlvContents []byte
		for i := pos + 2; i < pos+2+tlvLen; i++ {
			tlvContents = append(tlvContents, tlvBytes[i])
		}

		t := &rawTLV{
			Type:   uint8(tlvBytes[pos]),
			Length: uint8(tlvLen),
			Value:  tlvContents,
		}
		tlvs = append(tlvs, t)
	}

	return tlvs, nil
}

// processTLVMap maps the IS-IS TLV type to the function that parses the TLV.
var processTLVMap = map[uint8]func(*isisLSP, *rawTLV) error{
	1:   (*isisLSP).processAreaAddressTLV,
	22:  (*isisLSP).processExtendedISReachabilityTLV,
	129: (*isisLSP).processNLPIDTLV,
	132: (*isisLSP).processIPInterfaceAddressTLV,
	134: (*isisLSP).processTERouterIDTLV,
	135: (*isisLSP).processExtendedIPReachTLV,
	137: (*isisLSP).processDynamicNameTLV,
	232: (*isisLSP).processIPv6InterfaceAddressTLV,
	236: (*isisLSP).processIPv6ReachabilityTLV,
	242: (*isisLSP).processCapabilityTLV,
}

// processTLVs processes the set of TLVs that are stored in the rawTLVs slice of the
// receiver isisLSP, and populates the LSP field with the OpenConfig data model that
// corresponds to the TLVs contained in the message. Returns an error when parsing
// is not successful.
func (i *isisLSP) processTLVs() error {
	var pErr errlist.List

	for _, r := range i.rawTLVs {
		if f, ok := processTLVMap[r.Type]; ok {
			pErr.Add(f(i, r))
		} else {
			// TODO(robjs): Append this TLV to the undefined TLVs in the
			// OpenConfig data model.
		}
	}
	return pErr.Err()
}

// processDynamicNameTLV parses the Dynamic Name TLV as defined in RFC5301.
func (i *isisLSP) processDynamicNameTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_DYNAMIC_NAME, dynamicNameContainer)
	if err != nil {
		return err
	}

	tlv.Hostname.Hostname = append(tlv.Hostname.Hostname, string(r.Value))
	return nil
}

// processAreaAddressTLV parses the area addresses TLV (type = 1) defined
// in ISO10589.
func (i *isisLSP) processAreaAddressTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_AREA_ADDRESSES, areaAddressContainer)
	if err != nil {
		return err
	}

	// The encoding of this TLV is specified as a 1-byte length (L), followed by
	// an L-byte area address.
	var endPos int
	for x := 0; x < len(r.Value); x = endPos {
		addrLen := int(r.Value[x])
		endPos = x + 1 + addrLen
		if endPos > len(r.Value) {
			return fmt.Errorf("invalid length of address, %d, overflows TLV length %d at position %d, TLV contents: %v, currently parsed: %v", addrLen, len(r.Value), x, r.Value, tlv.AreaAddress.Address)
		}
		a := fmt.Sprintf("%s.%s", canonicalHexString([]byte{r.Value[x+1]}), canonicalHexString(r.Value[x+2:endPos]))
		tlv.AreaAddress.Address = append(tlv.AreaAddress.Address, a)
	}
	return nil
}

// processNLPIDTLV parses TLV 129 the NLPID (network layer protocol identifiers)
// that are supported by the intermediate system. Defined in RFC 1195.
func (i *isisLSP) processNLPIDTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_NLPID, nlpidContainer)
	if err != nil {
		return err
	}

	var pErr errlist.List
	for _, b := range r.Value {
		var v oc.E_OpenconfigIsis_Nlpid_Nlpid
		switch b {
		case 0xCC:
			v = oc.OpenconfigIsis_Nlpid_Nlpid_IPV4
		case 0x8E:
			v = oc.OpenconfigIsis_Nlpid_Nlpid_IPV6
		default:
			pErr.Add(fmt.Errorf("unknown NLPID specified: %v", b))
			continue
		}
		tlv.Nlpid.Nlpid = append(tlv.Nlpid.Nlpid, v)
	}

	return pErr.Err()
}

// processIPInterfaceAddressTLV processes the IP interface address TLV (type = 132)
// of an IS-IS LSP. Defined in RFC1195.
func (i *isisLSP) processIPInterfaceAddressTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_INTERFACE_ADDRESSES, ipv4InterfaceAddressContainer)
	if err != nil {
		return err
	}

	if (len(r.Value) % 4) != 0 {
		return fmt.Errorf("invalid IPv4 interface address TLV, length was not a multiple of 4: %d", len(r.Value))
	}

	var pErr errlist.List
	for x := 0; x < len(r.Value); x += 4 {
		ip4, err := ip4BytesToString(r.Value[x : x+4])
		if err != nil {
			pErr.Add(err)
			continue
		}
		tlv.Ipv4InterfaceAddresses.Address = append(tlv.Ipv4InterfaceAddresses.Address, ip4)
	}

	return pErr.Err()
}

// processIPv6InterfaceAddressTLV processes the IPv6 interface address TLV (type = 232)
// of an IS-IS LSP. Defined in RFC5308.
func (i *isisLSP) processIPv6InterfaceAddressTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_INTERFACE_ADDRESSES, ipv6InterfaceAddressContainer)
	if err != nil {
		return err
	}

	if (len(r.Value) % 16) != 0 {
		return fmt.Errorf("invalid IPv6 interface address TLV, length was not a multiple of 16: %d", len(r.Value))
	}

	for x := 0; x < len(r.Value); x += 16 {
		ip6, err := ip6BytesToString(r.Value[x : x+16])
		if err != nil {
			return err
		}
		tlv.Ipv6InterfaceAddresses.Address = append(tlv.Ipv6InterfaceAddresses.Address, ip6)
	}
	return nil
}

// processCapabilityTLV processes the Router Capability TLV (type = 242) of an
// IS-IS LSP. Defined in RFC7981. If the capability TLV contains subTLVs these
// are parsed and included in the TLV appended to the receiver.
func (i *isisLSP) processCapabilityTLV(r *rawTLV) error {
	tlv, _, err := i.getTLV(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_ROUTER_CAPABILITY)
	if err != nil {
		return err
	}

	// The Capability list is indexed based on the instance number, so
	// simply add a new one with the length of the list.
	rcap, err := tlv.NewCapability(uint32(len(tlv.Capability)))
	if err != nil {
		return err
	}

	// Encoding of this TLV is specified to be:
	// 4-bytes of router ID
	// 1 byte which includes:
	//	- down bit (bit index 6)
	//	- flood bit (bit index 7)
	// SubTLVs (variable length)
	if len(r.Value) < 5 {
		return fmt.Errorf("invalid length of Router Capability TLV; %d", len(r.Value))
	}
	rid, err := ip4BytesToString(r.Value[0:4])
	if err != nil {
		return err
	}
	rcap.RouterId = ygot.String(rid)

	if dbit := r.Value[4] & bit6; dbit != 0 {
		rcap.Flags = append(rcap.Flags, oc.OpenconfigIsis_Capability_Flags_DOWN)
	}
	if sbit := r.Value[4] & bit7; sbit != 0 {
		rcap.Flags = append(rcap.Flags, oc.OpenconfigIsis_Capability_Flags_FLOOD)
	}

	subTLVs, err := TLVBytesToTLVs(r.Value[5:])
	if err != nil {
		return fmt.Errorf("invalid subTLVs in Capability TLV: %v", err)
	}

	var pErr errlist.List
	for _, s := range subTLVs {
		switch s.Type {
		case 2:
			pErr.Add(processSRCapabilitySubTLV(rcap, s))
		case 19:
			pErr.Add(processSRAlgorithmCapabilitySubTLV(rcap, s))
		default:
			// TODO(robjs): Add this subTLV to the unknown subTLV list.
			pErr.Add(fmt.Errorf("unimplemented router capability sub-TLV, type: %d", s.Type))
		}
	}

	return pErr.Err()
}

// processSRAlgorithmCapabilitySubTLV parses the Segment Routing algorithm
// sub-TLV, sub-TLV type 19 of TLV 242. Defined in draft-ietf-isis-segment-routing-extensions.
// The sub-TLV is appended to the Capability TLV provided.
func processSRAlgorithmCapabilitySubTLV(c *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability, r *rawTLV) error {
	stlv, err := getCapabilitySubTLV(c, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_ALGORITHM)
	if err != nil {
		return err
	}

	stlv.SegmentRoutingAlgorithms = &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingAlgorithms{}
	var pErr errlist.List
	// The encoding of the algorithm TLV is 1-byte values per algorithm.
	for _, i := range r.Value {
		switch uint8(i) {
		case 0:
			stlv.SegmentRoutingAlgorithms.Algorithm = append(stlv.SegmentRoutingAlgorithms.Algorithm, oc.OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm_SPF)
		case 1:
			stlv.SegmentRoutingAlgorithms.Algorithm = append(stlv.SegmentRoutingAlgorithms.Algorithm, oc.OpenconfigIsis_SegmentRoutingAlgorithms_Algorithm_STRICT_SPF)
		default:
			pErr.Add(fmt.Errorf("invalid Segment Routing algorithm returned in router capability sub-TLV, algorithm: %d", i))
		}
	}

	return pErr.Err()
}

// processSRCapabilitySubTLV processes the Segment Routing capability
// sub-TLV, sub-TLV type 2, of TLV 242. Defined in draft-ietf-isis-segment-routing-extensions.
func processSRCapabilitySubTLV(c *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability, r *rawTLV) error {
	stlv, err := getCapabilitySubTLV(c, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_ROUTER_CAPABILITY_SR_CAPABILITY)
	if err != nil {
		return err
	}

	srcap := &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability{}
	// The encoding of the SR capabilities sub-TLV is as follows.
	// 1-byte of flags:
	//	bit 0: MPLS-IPv4 capability bit
	//	bit 1: MPLS-IPv6 capability bit
	//	(Quite why these are index 0 and 1 when the capability TLV uses index 6 and 7
	//	is not clear to this implementor.)
	// Repeated descriptor entries that consist of:
	//	3-octets range
	//	a SID/Label Sub-TLV encoded as:
	//		Type (1b)
	//		Length (1b)
	//		If length == 3, an MPLS label.
	//		If length == 4, a SID index.
	if ibit := r.Value[0] & bit0; ibit != 0 {
		srcap.Flags = append(srcap.Flags, oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV4_MPLS)
	}

	if vbit := r.Value[0] & bit1; vbit != 0 {
		srcap.Flags = append(srcap.Flags, oc.OpenconfigIsis_SegmentRoutingCapability_Flags_IPV6_MPLS)
	}

	var endPos int
	// Only store non-fatal errors in the parse error.
	var pErr errlist.List
	descrNo := uint32(0)
	for i := 1; i < len(r.Value); i += endPos {
		if len(r.Value) < i+8 {
			// Note that the length might be 9, but we just want
			// to check that we're not going to overflow at the
			// minimum.
			return fmt.Errorf("invalid length of SR descriptor entry, overflows TLV length")
		}
		// Read the length and do a length check to avoid panic in the
		// case that we have insufficient data.
		sidlLen := int(r.Value[i+4])
		if sidlLen == 4 && len(r.Value) < i+9 {
			return fmt.Errorf("invalid length of SR descriptor entry with an index, overflows TLV length")
		}
		endPos = 5 + sidlLen
		srgbRange, err := binaryToUint32([]byte{0, r.Value[i], r.Value[i+1], r.Value[i+2]})
		if err != nil {
			return err
		}

		sidlType := int(r.Value[i+3])
		if sidlType != 1 {
			pErr.Add(fmt.Errorf("invalid SID/Label sub-TLV type in SRGB descriptor: %d", sidlType))
		}
		sidlVal := r.Value[i+5 : i+5+int(sidlLen)]

		var lbl uint32
		switch sidlLen {
		case 3:
			lbl, err = binaryToUint32([]byte{0x0, sidlVal[0], sidlVal[1], sidlVal[2]})
		case 4:
			lbl, err = binaryToUint32(sidlVal)
		default:
			return fmt.Errorf("invalid length SRGB start: %d", sidlLen)
		}

		if err != nil {
			return err
		}

		descr, err := srcap.NewSrgbDescriptor(descrNo)
		if err != nil {
			return err
		}
		// Increment the entry number for subsequent SRGB descriptors.
		descrNo++

		descr.Label = &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Capability_Subtlv_SegmentRoutingCapability_SrgbDescriptor_Label_Union_Uint32{lbl}
		descr.Range = ygot.Uint32(srgbRange)
	}
	stlv.SegmentRoutingCapability = srcap

	return pErr.Err()
}

// processIPv6ReachabilityTLV parses the IPv6 Reachability TLV of an IS-IS LSP.
// Defined in RFC5308. Returns an error if one is encountered.
func (i *isisLSP) processIPv6ReachabilityTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV6_REACHABILITY, ipv6ReachabilityContainer)
	if err != nil {
		return err
	}

	// Encoding of this TLV is:
	// 4-bytes of metric
	// 1-byte of control:
	//	Bit 7 - up/down
	//	Bit 6 - external origin
	//	Bit 5 - subtlv present
	// 1 octet of prefix length
	// N octets of prefix
	// 1 octet of subTLV length
	// N octets of subTLV
	//
	// This structure can be repeated.

	// Used to track the size of the TLV instance.
	var s int
	var pErr errlist.List
	for x := 0; x < len(r.Value); x = s {
		if len(r.Value) < x+6 {
			// Must have at least metric, control, pfxlen
			return fmt.Errorf("invalid IPv6 Reachability TLV, insufficient data: %d < %d", len(r.Value), x+6)
		}

		metric, err := binaryToUint32(r.Value[x+0 : x+4])
		if err != nil {
			return err
		}

		var upDown, extOrigin, subTLVPresent bool
		if ubit := r.Value[x+4] & bit0; ubit != 0 {
			upDown = true
		}

		if ebit := r.Value[x+4] & bit1; ebit != 0 {
			extOrigin = true
		}

		if sbit := r.Value[x+4] & bit2; sbit != 0 {
			subTLVPresent = true
		}

		// The prefix length specifies both the mask and then the number of
		// octets that are packed into the TLV - such tha the encoding does
		// not always specify all 128b of the IPv6 address.
		pfxlen := int(r.Value[x+5])
		ipBytes := make([]byte, 16)
		ipL := int((pfxlen + 7) / 8)

		if len(r.Value) < x+6+ipL {
			return fmt.Errorf("Invalid prefix length, %d, overflows length of TLV %d", ipL, len(r.Value))
		}

		for j := 0; j < ipL; j++ {
			ipBytes[j] = r.Value[x+6+j]
		}

		addr, err := ip6BytesToString(ipBytes)
		if err != nil {
			return err
		}
		pfx := fmt.Sprintf("%s/%d", addr, pfxlen)

		// Track the current size of this TLV
		s = x + 6 + ipL

		if _, ok := tlv.Ipv6Reachability.Prefix[pfx]; ok {
			return err
		}

		pfxTLV := &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix{
			Prefix: ygot.String(pfx),
			UpDown: ygot.Bool(upDown),
			SBit:   ygot.Bool(subTLVPresent),
			XBit:   ygot.Bool(extOrigin),
			Metric: ygot.Uint32(metric),
		}

		if subTLVPresent {
			if len(r.Value) < s+1 {
				return errors.New("invalid length IPv6 Reachability TLV, subTLVs present but no length byte present")
			}

			subTLVLen := int(r.Value[s])

			if len(r.Value) < s+1+subTLVLen {
				// Underflow of the TLV is fatal.
				return fmt.Errorf("invalid length IPv6 Reachability subTLVs, subTLV length %d, but byte length %d", s+subTLVLen, len(r.Value))
			}

			subTLVs, err := TLVBytesToTLVs(r.Value[s+1 : s+1+subTLVLen])
			if err != nil {
				// Inability to parse TLVs is fatal.
				return fmt.Errorf("invalid subTLVs in IPv6 Reachability TLV: %v", err)
			}

			for _, st := range subTLVs {
				switch st.Type {
				case 3:
					pfxseg, err := parsePrefixSIDSubTLV(st)
					if err != nil {
						pErr.Add(err)
						break
					}
					if err := addIPv6ReachabilityPrefixSID(pfxTLV, pfxseg); err != nil {
						pErr.Add(err)
					}
				default:
					// TODO(robjs): Add this subTLV to the unknown subTLV list.
					pErr.Add(fmt.Errorf("unimplemented sub-TLV parsing for type %d in IPv6 Reachability TLV", st.Type))
				}
			}
			s += 1 + subTLVLen
		}

		if err := tlv.Ipv6Reachability.AppendPrefix(pfxTLV); err != nil {
			return fmt.Errorf("cannot append IPv6 Reachability TLV, %v", err)
		}
	}

	if s != len(r.Value) {
		return fmt.Errorf("invalid IPv6 Reachability TLV, does not have correct length: %d != %d, remaining bytes: %v", s, len(r.Value), r.Value[s:])
	}

	return pErr.Err()
}

// prefixSIDSubTLV describes sub-TLV3 of the IP reachability TLV types
// (i.e., 135, 235, 236, 237). It is used to store an arbitrary representation
// of the PrefixSID subTLV in a manner that does not require knowledge of where
// in the OpenConfig schema it is being parsed.
type prefixSIDSubTLV struct {
	Algorithm uint8                                 // Algorithm that the prefix SID is associated with.
	Value     uint32                                // Value of the SID.
	Flags     []oc.E_OpenconfigIsis_PrefixSid_Flags // Flags for the prefix SID.
}

// parsePrefixSIDSubTLV extracts a Prefix SID subTLV, returning a
// proprietary structure that stores its contents. The caller can
// fit this into the relevant type, dependent upon the context
// within which it was expected.
func parsePrefixSIDSubTLV(r *rawTLV) (*prefixSIDSubTLV, error) {
	p := &prefixSIDSubTLV{}

	// Perform a primary length check to ensure that we do
	// not panic.
	if len(r.Value) < 4 {
		return nil, fmt.Errorf("invalid Prefix-SID subTLV, invalid length: %d", len(r.Value))
	}

	if b := r.Value[0] & bit0; b != 0 {
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_READVERTISEMENT)
	}

	if b := r.Value[0] & bit1; b != 0 {
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_NODE)
	}

	if b := r.Value[0] & bit2; b != 0 {
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_NO_PHP)
	}

	if b := r.Value[0] & bit3; b != 0 {
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_EXPLICIT_NULL)
	}

	var isLabel bool
	if b := r.Value[0] & bit4; b != 0 {
		isLabel = true
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_VALUE)
		// This also means that the value should be 4-bytes long rather than 3,
		// so we check that the length will not cause a panic later.
		if len(r.Value) < 5 {
			return nil, fmt.Errorf("invalid Prefix-SID subTLV, invalid length for index: %d", len(r.Value))
		}
	}

	if b := r.Value[0] & bit5; b != 0 {
		p.Flags = append(p.Flags, oc.OpenconfigIsis_PrefixSid_Flags_LOCAL)
	}

	p.Algorithm = r.Value[1]

	var sidv uint32
	if !isLabel {
		var err error
		// This is an index, so we have a 4-byte value to parse.
		if sidv, err = binaryToUint32(r.Value[2:6]); err != nil {
			return nil, err
		}
	} else {
		var err error
		// This is an MPLS label, so 3-bytes to parse.
		if sidv, err = binaryToUint32([]byte{0, r.Value[2], r.Value[3], r.Value[4]}); err != nil {
			return nil, err
		}
	}
	p.Value = sidv

	return p, nil
}

// addIPv6ReachabilityPrefixSID adds the contents of a prefixSIDSubTLV to the supplied
// IPv6 Reachability prefix TLV. Return an error if adding the contents is not possible.
func addIPv6ReachabilityPrefixSID(c *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_Ipv6Reachability_Prefix, p *prefixSIDSubTLV) error {
	subtlv, err := c.NewSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID)
	if err != nil {
		return err
	}

	pfxsid, err := subtlv.NewPrefixSid(p.Value)
	if err != nil {
		return err
	}

	pfxsid.Algorithm = ygot.Uint8(p.Algorithm)
	pfxsid.Flags = p.Flags

	return nil
}

// processTERouterIDTLV parses TLV type 134, extracting the 4-byte TE Router ID.
// Defined by RFC5305. Returns an error if the input is invalid.
func (i *isisLSP) processTERouterIDTLV(r *rawTLV) error {
	if len(r.Value) < 4 || len(r.Value) > 4 {
		return fmt.Errorf("invalid length Router ID TLV: %d", len(r.Value))
	}

	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_IPV4_TE_ROUTER_ID, ipv4TERouterIDContainer)
	if err != nil {
		return err
	}

	ip4, err := ip4BytesToString(r.Value[0:4])
	if err != nil {
		return err
	}

	tlv.Ipv4TeRouterId.RouterId = append(tlv.Ipv4TeRouterId.RouterId, ip4)
	return nil
}

// processExtendedISReachabilityTLV parses TLV type 22. Defined by RFC5305.
// Returns an error if the input is invalid.
func (i *isisLSP) processExtendedISReachabilityTLV(r *rawTLV) error {
	if len(r.Value) < 11 {
		return fmt.Errorf("invalid Extended IS Reachability TLV (22), length is less than 11 bytes")
	}

	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IS_REACHABILITY, extendedISReachabilityContainer)
	if err != nil {
		return err
	}

	// Encoding for this TLV is a set of entries, each of which consist
	// of:
	// 7b system ID
	// 3b default metric
	// 1 octet of sub-TLV length
	// If subTLV length > 0:
	//	1 octet sub-TLV type
	//	1 octet length
	// 0-242 octet value

	var pErr errlist.List
	var endPos int
	for x := 0; x < len(r.Value); x = endPos {
		if len(r.Value) < x+11 {
			pErr.Add(fmt.Errorf("invalid length IS Reachability TLV, byte offset %d, total TLV length %d", x, len(r.Value)))
			//Break here since we cannot read any further if we are out of bytes.
			break
		}

		subTLVLen := int(r.Value[x+10])
		if len(r.Value) < x+11+subTLVLen {
			pErr.Add(fmt.Errorf("invalid length IS Reachability TLV, byte offset %d, subTLV length %d", x, subTLVLen))
			break
		}
		subTLVs, err := TLVBytesToTLVs(r.Value[x+11 : x+11+int(subTLVLen)])
		if err != nil {
			pErr.Add(fmt.Errorf("invalid subTLVs in ExtendedISReachability TLV: %v", err))
			break
		}

		endPos = x + subTLVLen + 11

		defmetric, err := binaryToUint32([]byte{0, r.Value[x+7], r.Value[x+8], r.Value[x+9]})
		if err != nil {
			pErr.Add(err)
			continue
		}

		nid := canonicalHexString(r.Value[x : x+7])
		var n *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor

		if t, ok := tlv.ExtendedIsReachability.Neighbor[nid]; ok {
			n = t
		} else {
			newn, err := tlv.ExtendedIsReachability.NewNeighbor(nid)
			if err != nil {
				pErr.Add(err)
				continue
			}
			n = newn
		}

		// Create a new instance of the TLV, since there can be multiple
		// adjacencies between the same two ISes. There is no expectation
		// that two instances will have the same identifier with subsequent
		// parses of an LSP if the order changes.
		// It is always safe to call GetOrCreate here since we dynamically
		// compute the key.
		inst := n.GetOrCreateInstance(uint64(len(n.Instance)))

		inst.Metric = ygot.Uint32(defmetric)

		if err := parseExtendedISReachSubTLVs(inst, subTLVs); err != nil {
			pErr.Add(err)
			continue
		}
	}

	return pErr.Err()
}

// parseExtendedISReachSubTLVs parses the subTLVs of the extended IS reachability
// TLV, appending them to the instance provided. Returns an error if parsing is
// unsuccesful.
func parseExtendedISReachSubTLVs(n *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance, subTLVs []*rawTLV) error {
	var pErr errlist.List
	for _, s := range subTLVs {
		switch s.Type {
		case 3:
			a, err := parseAdministrativeGroupSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADMIN_GROUP, extISReachAdminGroupContainer)
			if err != nil {
				pErr.Add(err)
				continue
			}
			tlv.AdminGroup.AdminGroup = append(tlv.AdminGroup.AdminGroup, a)
		case 4:
			local, remote, err := parseLinkLocalRemoteSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}
			n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_LINK_ID).LinkId = &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LinkId{
				Local:  ygot.Uint32(local),
				Remote: ygot.Uint32(remote),
			}
		case 6:
			a, err := parseIPv4InterfaceSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_INTERFACE_ADDRESS, extISReachIPv4InterfaceAddress)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv.Ipv4InterfaceAddress.Address = append(tlv.Ipv4InterfaceAddress.Address, a)
		case 8:
			a, err := parseIPv4InterfaceSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_IPV4_NEIGHBOR_ADDRESS, extISReachIPv4NeighborAddress)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv.Ipv4NeighborAddress.Address = append(tlv.Ipv4NeighborAddress.Address, a)
		case 9:
			b, err := parseLinkBandwidthSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_LINK_BANDWIDTH, extISReachMaxLinkBW)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv.MaxLinkBandwidth.Bandwidth = b
		case 10:
			b, err := parseLinkBandwidthSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_MAX_RESERVABLE_BANDWIDTH, extISReachMaxReservableBW)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv.MaxReservableLinkBandwidth.Bandwidth = b
		case 11:
			ubw, err := parseUnreservedBandwidthSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			st, err := n.NewSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_UNRESERVED_BANDWIDTH)
			if err != nil {
				pErr.Add(err)
				continue
			}

			for pri, bw := range ubw {
				if err := st.AppendSetupPriority(&oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_SetupPriority{
					Priority:  ygot.Uint8(pri),
					Bandwidth: bw,
				}); err != nil {
					pErr.Add(fmt.Errorf("error adding bandwidth at priority level %d - %v", pri, err))
					continue
				}
			}

		case 31:
			adjs, err := parseAdjSIDSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			if err = n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_SID).AppendAdjacencySid(adjs); err != nil {
				pErr.Add(err)
				continue
			}

		case 32:
			adjs, err := parseLANAdjSIDSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			if err := n.GetOrCreateSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_ADJ_LAN_SID).AppendLanAdjacencySid(adjs); err != nil {
				pErr.Add(err)
				continue
			}

		case 38:
			b, err := parseLinkBandwidthSubTLV(s)
			if err != nil {
				pErr.Add(err)
				continue
			}

			tlv, err := getExtendedISReachSubTLV(n, oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IS_REACHABILITY_RESIDUAL_BANDWIDTH, extISReachResidualBW)
			if err != nil {
				pErr.Add(err)
				continue
			}
			tlv.ResidualBandwidth.Bandwidth = b
		default:
			// TODO(robjs): Append to undefined subTLV list.
			continue
		}
	}

	return pErr.Err()
}

// parseAdministrativeGroupSubTLV parses sub-TLV 3 of the IS adjacency TLVs,
// 22, 23, 141, 222 and 223. Returns a uint32 representing the bitmask in
// the TLV, or an error if one is encountered.
func parseAdministrativeGroupSubTLV(r *rawTLV) (uint32, error) {
	// Length errors are checked by binaryToUint32 - so no explicit check.
	mask, err := binaryToUint32(r.Value)
	if err != nil {
		return 0, err
	}
	return mask, nil
}

// parseLinkLocalRemoteSubTLV parses sub-TLV 4 of the IS adjacency TLVs
// 22, 23, 141, 222 and 223. It returns two uint32s, the first specifies
// the local link ID, and the second being the remote link ID. The link
// local and remote identifier sub-TLV is defined in RFC5307.
func parseLinkLocalRemoteSubTLV(r *rawTLV) (uint32, uint32, error) {
	if r.Length != 8 || len(r.Value) != 8 {
		return 0, 0, fmt.Errorf("invalid length for link local/remote identifier sub-TLV %d", len(r.Value))
	}

	local, err := binaryToUint32(r.Value[0:4])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid contents of local identifier %v", err)
	}

	remote, err := binaryToUint32(r.Value[4:])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid contents of remote identifier %v", err)
	}

	return local, remote, nil
}

// parseIPv4InterfaceSubTLV parses sub-TLV 6 or 8 of the IS adjacency
// TLVs 22, 23, 141, 222 and 223. Returns a string containing the IPv4
// address which is within the TLV, or an error if encountered.
func parseIPv4InterfaceSubTLV(r *rawTLV) (string, error) {
	if len(r.Value) != 4 {
		return "", fmt.Errorf("IPv4 interface sub-TLV (type %d) had incorrect length: %d != 4", r.Type, len(r.Value))
	}
	addr, err := ip4BytesToString(r.Value)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// parseLinkBandwidthSubTLV parses sub-TLV 9 or 10 of the IS adjacency TLVs 22,
// 23, 141, 222 and 223. Returns a []byte containing a float32 representing the
// bandwidth level communicated within the TLV, or an error if encountered.
func parseLinkBandwidthSubTLV(r *rawTLV) ([]byte, error) {
	// Length errors checked by binaryToFloat32.
	if _, err := binaryToFloat32(r.Value); err != nil {
		return nil, err
	}
	return r.Value, nil
}

// parseUnreservedBandwidthSubTLV parses sub-TLV 11 of TLVs 22, 23, 25, 141, 222
// and 223 extracting the bandwidth per priority level. It returns a map, keyed by
// priority level, of the unreserved bandwidth reported within the TLV.
func parseUnreservedBandwidthSubTLV(r *rawTLV) (map[uint8][]byte, error) {
	if r.Length != 32 || len(r.Value) != 32 {
		return nil, fmt.Errorf("invalid length for unreserved bandwidth TLV %d", r.Length)
	}

	// The TLV is encoded as a series of float32 values, each of which
	// represents the unreserved bandwidth at each of priority levels
	// 0 through 7.
	out := map[uint8][]byte{}
	for i := 0; i < int(r.Length); i += 4 {
		if _, err := binaryToFloat32(r.Value[i : i+4]); err != nil {
			return nil, fmt.Errorf("invalid unreserved bandwidth at priority level %d", len(out))
		}
		out[uint8(len(out))] = r.Value[i : i+4]
	}
	return out, nil
}

// parseLocalRemoteLinkIDSubTLV parses sub-TLV 4 of the IS adjacency
// TLVs 22, 23, 141, 222 and 223. Returns two uint, the first of
// which is the local link ID, and the second of which is the
// remote; or an error if one is encountered.
func parseLocalRemoteLinkIDSubTLV(r *rawTLV) (uint32, uint32, error) {
	if len(r.Value) != 8 {
		return 0, 0, fmt.Errorf("incorrect length for local/remote link ID TLV: %d != 8", len(r.Value))
	}

	lid, err := binaryToUint32(r.Value[0:4])
	if err != nil {
		return 0, 0, err
	}

	rid, err := binaryToUint32(r.Value[4:8])
	if err != nil {
		return 0, 0, err
	}

	return lid, rid, nil
}

// parseAdjSIDSubTLV parses sub-TLV 31 of the IS adjacency TLVs 22, 23,
// 141, 222, and 223. It returns the populated OpenConfig struct for the Adj-SID
// subTLV.
func parseAdjSIDSubTLV(r *rawTLV) (*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid, error) {
	if len(r.Value) < 5 {
		// Length must be a minimum of:
		//  - 1 byte flagByte
		//  - 1 byte weight
		//  - 3 byte SID (can be 4 bytes if an index)
		return nil, fmt.Errorf("invalid length for adjacency SID %d bytes", len(r.Value))
	}

	flags, isLocal, isValue := adjSIDFlags(r.Value[0])

	weight, err := binaryToUint32([]byte{0, 0, 0, r.Value[1]})
	if err != nil {
		return nil, fmt.Errorf("cannot parse weight in adjacency SID, %v", err)
	}

	value, err := adjSIDValue(r.Value[2:], isValue, isLocal)
	if err != nil {
		return nil, err
	}

	return &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_AdjacencySid{
		Value:  ygot.Uint32(value),
		Flags:  flags,
		Weight: ygot.Uint8(uint8(weight)),
	}, nil
}

// parseLANAdjSIDSubTLV parses the LAN Adjacency Segment Identifier (TLV ID 32) subTLV of the
// Extended IS Reachability TLVs (22, 23, 222, 223). It returns the populated OpenConfig
// struct for the LAN Adjacency SID sub-TLV.
func parseLANAdjSIDSubTLV(r *rawTLV) (*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid, error) {
	if len(r.Value) < 8 {
		// Length must be a minimum of
		//  - 1 byte flags
		//  - 1 byte weight
		//  - 6 byte system ID
		return nil, fmt.Errorf("invalid length for LAN AdjSID subTLV %d", len(r.Value))
	}

	flags, isLocal, isValue := lanAdjSIDFlags(r.Value[0])

	weight, err := binaryToUint32([]byte{0, 0, 0, r.Value[1]})
	if err != nil {
		return nil, fmt.Errorf("cannot parse weight in LAN adjacency SID, %v", err)
	}

	neighID := canonicalHexString(r.Value[2:8])

	value, err := adjSIDValue(r.Value[8:], isValue, isLocal)
	if err != nil {
		return nil, err
	}

	return &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIsReachability_Neighbor_Instance_Subtlv_LanAdjacencySid{
		Value:      ygot.Uint32(value),
		Flags:      flags,
		Weight:     ygot.Uint8(uint8(weight)),
		NeighborId: ygot.String(neighID),
	}, nil
}

// adjSIDFlags parses the flag byte of the Adj-SID Extended IS Reachability TLV
// sub-TLV. It returns a slice containing the OpenConfig enumerated value
// indicating the flags, and a pair of bools which indicate whether the value
// and local flags are set.
func adjSIDFlags(flagByte uint8) ([]oc.E_OpenconfigIsis_AdjacencySid_Flags, bool, bool) {
	var flags []oc.E_OpenconfigIsis_AdjacencySid_Flags
	if b := flagByte & bit0; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_AdjacencySid_Flags_ADDRESS_FAMILY)
	}

	if b := flagByte & bit1; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_AdjacencySid_Flags_BACKUP)
	}

	var isValue bool
	if b := flagByte & bit2; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_AdjacencySid_Flags_VALUE)
		isValue = true
	}

	var isLocal bool
	if b := flagByte & bit3; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_AdjacencySid_Flags_LOCAL)
		isLocal = true
	}

	if b := flagByte & bit4; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_AdjacencySid_Flags_SET)
	}

	// TODO(robjs): OpenConfig model is currently missing the persistent flag.

	return flags, isValue, isLocal
}

// lanAdjIDFlags parses the flag byte of the Extended IS Reachability TLV
// LAN AdjSID Extended IS Reachability sub-TLVs. It returns a slice
// containing the OpenConfig enumerated value indicating the flags, and a pair
// of bools which indicate whether the value and local flags are set.
// TODO(robjs): Consider whether there should be a common typedef here in the OC
// model. It is possible these two sets of bits will diverge in the future.
func lanAdjSIDFlags(flagByte uint8) ([]oc.E_OpenconfigIsis_LanAdjacencySid_Flags, bool, bool) {
	var flags []oc.E_OpenconfigIsis_LanAdjacencySid_Flags
	if b := flagByte & bit0; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_LanAdjacencySid_Flags_ADDRESS_FAMILY)
	}

	if b := flagByte & bit1; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_LanAdjacencySid_Flags_BACKUP)
	}

	var isValue bool
	if b := flagByte & bit2; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_LanAdjacencySid_Flags_VALUE)
		isValue = true
	}

	var isLocal bool
	if b := flagByte & bit3; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_LanAdjacencySid_Flags_LOCAL)
		isLocal = true
	}

	if b := flagByte & bit4; b != 0 {
		flags = append(flags, oc.OpenconfigIsis_LanAdjacencySid_Flags_SET)
	}

	// TODO(robjs): OpenConfig model is currently missing the persistent flag.

	return flags, isValue, isLocal
}

// adjSIDValue parses the value from an adjacency SID subTLV (LAN or link) and returns
// the value it contains as an uint32. The isValue and isLocal bools indicate whether the
// VALUE and LOCAL flags respectively were set in the sub-TLV, and are used for error
// checking.
func adjSIDValue(valbytes []byte, isValue, isLocal bool) (uint32, error) {
	switch {
	case isValue && isLocal:
		if l := len(valbytes); l != 3 {
			// If the length isn't 3, then there is not a valid MPLS label contained here.
			return 0, fmt.Errorf("invalid length for adjacency SID containing label %d", l)
		}
		value, err := binaryToUint32([]byte{0, valbytes[0], valbytes[1], valbytes[2]})
		if err != nil {
			return 0, fmt.Errorf("invalid label in adjacency SID subTLV %v", err)
		}
		return value, nil
	case !isValue && !isLocal:
		if l := len(valbytes); l != 4 {
			return 0, fmt.Errorf("invalid length for adjacency SID containing index %d", l)
		}
		value, err := binaryToUint32(valbytes[0:4])
		if err != nil {
			return 0, fmt.Errorf("invalid index for adjacency SID subTLV %v", err)
		}
		return value, nil
	}
	return 0, fmt.Errorf("invalid combination of value and local flagByte, value: %v, local: %v", isValue, isLocal)
}

// processExtendedIPReachTLV process the Extended IP Reachability TLV (type 135).
// Defined by RFC5305. Returns an error if any is encountered during processing.
func (i *isisLSP) processExtendedIPReachTLV(r *rawTLV) error {
	tlv, err := i.getTLVAndInit(oc.OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE_EXTENDED_IPV4_REACHABILITY, extendedIPv4ReachabilityContainer)
	if err != nil {
		return err
	}

	// Encoding of this TLV is:
	// 4-octets of metric.
	// 1 octet of control:
	//	1 bit up/down
	//	1 bit subTLVs present
	//	6 bits of prefix length
	// 0-4 bytes of prefix
	// 1 octet of subTLV length
	// N octets of subTLVs
	//
	// This TLV structure can be repeated.

	// Used to track the size of the TLV instance.
	var s int
	var pErr errlist.List
	for x := 0; x < len(r.Value); x = s {
		if len(r.Value) < x+5 {
			// Must have at least the metric and control bytes present.
			return fmt.Errorf("invalid Extended IP Reachability TLV, insufficient data - at position %d, total length: %d", x, len(r.Value))
		}
		metric, err := binaryToUint32(r.Value[x : x+4])
		if err != nil {
			return err
		}

		var upDown, subTLVPresent bool
		if ubit := r.Value[x+4] & bit0; ubit != 0 {
			upDown = true
		}

		if sbit := r.Value[x+4] & bit1; sbit != 0 {
			subTLVPresent = true
		}

		pfxLen := int(r.Value[x+4] &^ 0xC0) // clear bits 0 and 1
		if pfxLen > 32 {
			// Fatal as we cannot determine how many bytes the
			// prefix might use.
			return fmt.Errorf("IPv4 prefix length cannot be greater than 32: %d", pfxLen)
		}
		ipBytes := make([]byte, 4)
		ipB := int((pfxLen + 7) / 8)

		if len(r.Value) < x+5+ipB {
			// Fatal as we will panic in the parsing of the address if this is not the case.
			return fmt.Errorf("insufficient bytes for IPv4 prefix within TLV, length: %d, expected: %d", len(r.Value), x+5+ipB)
		}

		for j := 0; j < ipB; j++ {
			ipBytes[j] = r.Value[x+5+j]
		}

		pfx, err := ip4BytesToString(ipBytes)
		if err != nil {
			pErr.Add(err)
			continue
		}
		v4Pfx := fmt.Sprintf("%s/%d", pfx, pfxLen)

		// Track current size of the TLV
		s = x + 5 + ipB

		if _, ok := tlv.ExtendedIpv4Reachability.Prefix[v4Pfx]; ok {
			return err
		}

		pfxTLV := &oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix{
			Prefix: ygot.String(v4Pfx),
			Metric: ygot.Uint32(metric),
			SBit:   ygot.Bool(subTLVPresent),
			UpDown: ygot.Bool(upDown),
		}

		if subTLVPresent {
			if len(r.Value) < s+1 {
				return fmt.Errorf("invalid length Extended IP Reachability TLV, subTLVs present but no length byte exists")
			}

			subTLVLen := int(r.Value[s])

			if len(r.Value) < s+1+subTLVLen {
				return fmt.Errorf("invalid length Extended IP Reachability TLV, subTLV length %d but byte length %d", s+subTLVLen, len(r.Value))
			}

			subTLVs, err := TLVBytesToTLVs(r.Value[s+1 : s+1+subTLVLen])
			if err != nil {
				return fmt.Errorf("invalid sub-TLVs in ExtendedIPReachability TLV: %v", err)
			}

			for _, st := range subTLVs {
				switch st.Type {
				case 3:
					pfxseg, err := parsePrefixSIDSubTLV(st)
					if err != nil {
						pErr.Add(err)
						continue
					}

					if err := addExtendedIPReachabilityPrefixSID(pfxTLV, pfxseg); err != nil {
						pErr.Add(err)
					}
				default:
					// TODO(robjs): Add to unknown subTLV list.
					pErr.Add(fmt.Errorf("for prefix %s unimplemented sub-TLV parsing for type %d in Extended IP Reachability TLV", v4Pfx, st.Type))
				}
			}
			s += 1 + subTLVLen
		}

		if tlv.ExtendedIpv4Reachability.Prefix == nil {
			tlv.ExtendedIpv4Reachability.Prefix = make(map[string]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix)
		}
		tlv.ExtendedIpv4Reachability.Prefix[v4Pfx] = pfxTLV
	}

	return pErr.Err()
}

// addExtendedIPReachabilityPrefixSID adds the content of a prefixSIDSubTLV to the supplied
// Extended IPv4 Reachability prefix TLV. Returns an error if adding the contents is not
// possible.
func addExtendedIPReachabilityPrefixSID(c *oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv_ExtendedIpv4Reachability_Prefix, p *prefixSIDSubTLV) error {
	subtlv, err := c.NewSubtlv(oc.OpenconfigIsisLsdbTypes_ISIS_SUBTLV_TYPE_IP_REACHABILITY_PREFIX_SID)
	if err != nil {
		return err
	}

	pfxsid, err := subtlv.NewPrefixSid(p.Value)
	if err != nil {
		return err
	}

	pfxsid.Algorithm = ygot.Uint8(p.Algorithm)
	pfxsid.Flags = p.Flags

	return nil
}

// parseLSPFlags parses the contents of the LSP flags field, and returns
// a slice of the OpenConfig enumerated type for LSP flags for each flag that is
// set in the attrs byte.
func parseLSPFlags(attrs uint8) []oc.E_OpenconfigIsis_Lsp_Flags {
	var flags []oc.E_OpenconfigIsis_Lsp_Flags
	bitmap := map[uint8]oc.E_OpenconfigIsis_Lsp_Flags{
		bit0: oc.OpenconfigIsis_Lsp_Flags_PARTITION_REPAIR,
		bit1: oc.OpenconfigIsis_Lsp_Flags_ATTACHED_ERROR,
		bit2: oc.OpenconfigIsis_Lsp_Flags_ATTACHED_EXPENSE,
		bit3: oc.OpenconfigIsis_Lsp_Flags_ATTACHED_DELAY,
		bit4: oc.OpenconfigIsis_Lsp_Flags_ATTACHED_DEFAULT,
		bit5: oc.OpenconfigIsis_Lsp_Flags_OVERLOAD,
	}

	for bit, flag := range bitmap {
		if b := attrs & bit; b != 0 {
			flags = append(flags, flag)
		}
	}
	return flags
}
