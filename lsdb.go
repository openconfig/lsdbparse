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

// Package lsdbparse parses a binary IS-IS Link State PDU (LSP), storing the
// information as an instance of the OpenConfig (www.openconfig.net) IS-IS
// LSP PDU model.
package lsdbparse

import (
	"fmt"
	"time"

	"github.com/openconfig/gnmi/errlist"
	"github.com/openconfig/lsdbparse/pkg/oc"
	"github.com/openconfig/ygot/ygot"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// rawTLV stores the raw bytes of an extracted TLV from an LSP. The TLV
// can be a top-level IS-IS LSP TLV, or a subTLV of another TLV.
type rawTLV struct {
	Type   uint8  // Type is the 1-byte type of the TLV.
	Length uint8  // Length is the number of bytes contained in the value of the TLV.
	Value  []byte // Value is the bytes contained within the TLV.
}

// isisLSP is a wrapper struct that is used to contain both the parsed and
// unparsed copies of the LSP that is being processed.
type isisLSP struct {
	// LSP is the parsed LSP represented as per the OpenConfig model.
	LSP *oc.NetworkInstance_Protocol_Isis_Level_Lsp
	// rawTLVs is the set of the TLVs that are included within the
	// LSP as raw bytes.
	rawTLVs []*rawTLV
}

// newISISLSP is a helper function that creates an internal isisLSP
// struct to be used to store a parsed LSP.
func newISISLSP() *isisLSP {
	return &isisLSP{
		LSP: &oc.NetworkInstance_Protocol_Isis_Level_Lsp{
			Tlv: map[oc.E_OpenconfigIsisLsdbTypes_ISIS_TLV_TYPE]*oc.NetworkInstance_Protocol_Isis_Level_Lsp_Tlv{},
		},
		rawTLVs: []*rawTLV{},
	}
}

// ISISBytesToLSP takes an input slice of bytes that contain an IS-IS LSP starting
// at the LSP ID field. If there are additional bytes prior to this field, they can
// be discarded by specifying a non-zero offset.
// It extracts the LSP information and returns
// the OpenConfig /network-instances/network-instance/protocols/protocol/isis/levels/ +
// level/link-state-database/lsp structure that contains the parsed content.
// Returns a boolean, indicating whether any parsing of the LSP was possible, along with
// any errors that are encountered. In the case that the bool is set to true, error may be
// populated indicating that the LSP's contents were not completely succesfully parsed.
// This function is specifically for Cisco IOS XR devices, since it handles the case
// where a number of fields of the LSP are not included within the byte slice.
func ISISBytesToLSP(lspBytes []byte, offset int) (*oc.NetworkInstance_Protocol_Isis_Level_Lsp, bool, error) {
	lspBytes = lspBytes[offset:]

	if len(lspBytes) < 16 {
		return nil, false, fmt.Errorf("invalid LSP data provided, need at least 16 bytes, got %d bytes", len(lspBytes))
	}

	seq, err := binaryToUint32(lspBytes[8:12])
	if err != nil {
		return nil, false, err
	}

	checksum, err := binaryToUint32([]byte{0, 0, lspBytes[12], lspBytes[13]})
	if err != nil {
		return nil, false, err
	}

	tlvs, err := TLVBytesToTLVs(lspBytes[15:])
	if err != nil {
		return nil, false, fmt.Errorf("invalid TLVs in LSP: %v", err)
	}

	i := newISISLSP()
	i.LSP.LspId = ygot.String(fmt.Sprintf("%s-%s", canonicalHexString(lspBytes[0:7]), canonicalHexString([]byte{lspBytes[7]})))

	i.LSP.SequenceNumber = ygot.Uint32(seq)
	i.LSP.Checksum = ygot.Uint16(uint16(checksum))
	i.LSP.Flags = parseLSPFlags(lspBytes[14])

	i.rawTLVs = tlvs

	var pErr errlist.List
	if err := i.processTLVs(); err != nil {
		if e, ok := err.(errlist.Error); ok {
			pErr.Add(e.Errors()...)
		} else {
			pErr.Add(e)
		}
	}

	// TODO(robjs): Ensure that metrics with value 0 are supported in public
	// model.
	//pErr.Add(i.LSP.Validate().(util.Errors))

	return i.LSP, true, pErr.Err()
}

// ISISRenderArgs provides the arguments to the RenderNotifications functions,
// and provides the context for outputting an IS-IS LSP.
type ISISRenderArgs struct {
	// NetworkInstance is the network instance that the IS-IS instance is within.
	NetworkInstance string
	// ProtocolInstance is the name of the IS-IS instance.
	ProtocolInstance string
	// Level is the IS-IS level that the LSP is within.
	Level int
	// Timestamp is the timestamp for the generated notifications.
	Timestamp time.Time
	// UsePathElem specifies whether gNMI paths using the PathElem field should be
	// produced.
	UsePathElem bool
}

// RenderNotifications takes an input IS-IS LSP and outputs the gNMI Notifications that
// represent the contents of the supplied LSP. The ISISRenderArgs struct provided gives
// the context for the generation. Returns a set of gNMI notifications, or an error.
func RenderNotifications(lsp *oc.NetworkInstance_Protocol_Isis_Level_Lsp, args ISISRenderArgs) ([]*gnmipb.Notification, error) {
	if lsp == nil {
		return nil, fmt.Errorf("cannot handle nil LSP")
	}

	if lsp.LspId == nil {
		return nil, fmt.Errorf("cannot handle nil LSP ID in %v", lsp)
	}

	rArgs := ygot.GNMINotificationsConfig{
		UsePathElem: args.UsePathElem,
		StringSlicePrefix: []string{
			"network-instances", "network-instance", args.NetworkInstance,
			"protocols", "protocol", "ISIS", args.ProtocolInstance,
			"isis", "levels", "level", fmt.Sprintf("%d", args.Level),
			"link-state-database", "lsp", *lsp.LspId,
		},
	}

	if args.UsePathElem {
		p, err := ygot.StringToStructuredPath(fmt.Sprintf("/network-instances/network-instance[name=%s]/protocols/protocol[identifier=ISIS][name=%s]/isis/levels/level[level-number=%d]/link-state-database/lsp[lsp-id=%s]", args.NetworkInstance, args.ProtocolInstance, args.Level, *lsp.LspId))
		if err != nil {
			return nil, fmt.Errorf("cannot create prefix path, %v", err)
		}
		rArgs.PathElemPrefix = p.Elem
		rArgs.StringSlicePrefix = nil
	}

	notifications, err := ygot.TogNMINotifications(lsp, args.Timestamp.UnixNano(), rArgs)
	if err != nil {
		return nil, err
	}
	// IS-IS LSPs are atomically updated.
	for _, n := range notifications {
		n.Atomic = true
	}
	return notifications, nil
}
