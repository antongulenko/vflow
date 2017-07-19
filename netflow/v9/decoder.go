//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    decoder.go
//: details: decodes netflow version 9 packets
//: author:  Mehrdad Arshad Rad
//: date:    04/10/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package netflow9

import (
	"fmt"
	"io"
	"net"

	"github.com/VerizonDigital/vflow/ipfix"
	"github.com/VerizonDigital/vflow/reader"
)

// PacketHeader represents Netflow v9  packet header
type PacketHeader struct {
	Version   uint16 // Version of Flow Record format exported in this packet
	Count     uint16 // The total number of records in the Export Packet
	SysUpTime uint32 // Time in milliseconds since this device was first booted
	UNIXSecs  uint32 // Time in seconds since 0000 UTC 197
	SeqNum    uint32 // Incremental sequence counter of all Export Packets
	SrcID     uint32 // A 32-bit value that identifies the Exporter
}

// SetHeader represents netflow v9 data flowset id and length
type SetHeader struct {
	FlowSetID uint16 // FlowSet ID value 0:: template, 1:: options template, 255< :: data
	Length    uint16 // Total length of this FlowSet
}

// TemplateHeader represents netflow v9 data template id and field count
type TemplateHeader struct {
	TemplateID     uint16 // Template ID
	FieldCount     uint16 // Number of fields in this Template Record
	OptionLen      uint16 // The length in bytes of any Scope field definition (Option)
	OptionScopeLen uint16 // The length in bytes of any options field definitions (Option)
}

// TemplateFieldSpecifier represents field properties
type TemplateFieldSpecifier struct {
	ElementID uint16
	Length    uint16
}

// TemplateRecord represents template fields
type TemplateRecord struct {
	TemplateID           uint16
	FieldCount           uint16
	FieldSpecifiers      []TemplateFieldSpecifier
	ScopeFieldCount      uint16
	ScopeFieldSpecifiers []TemplateFieldSpecifier
}

// DecodedField represents a decoded field
type DecodedField struct {
	ID    uint16
	Value interface{}
}

// Decoder represents Netflow payload and remote address
type Decoder struct {
	raddr  net.IP
	reader *reader.Reader
}

// Message represents Netflow decoded data
type Message struct {
	AgentID  string
	Header   PacketHeader
	DataSets [][]DecodedField
}

//   The Packet Header format is specified as:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Version Number          |            Count              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           sysUpTime                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           UNIX Secs                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Sequence Number                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Source ID                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (h *PacketHeader) unmarshal(r *reader.Reader) error {
	var err error

	if h.Version, err = r.Uint16(); err != nil {
		return err
	}

	if h.Count, err = r.Uint16(); err != nil {
		return err
	}

	if h.SysUpTime, err = r.Uint32(); err != nil {
		return err
	}

	if h.UNIXSecs, err = r.Uint32(); err != nil {
		return err
	}

	if h.SeqNum, err = r.Uint32(); err != nil {
		return err
	}

	if h.SrcID, err = r.Uint32(); err != nil {
		return err
	}

	return nil
}

func (h *PacketHeader) validate() error {
	if h.Version != 9 {
		return fmt.Errorf("invalid netflow version (%d)", h.Version)
	}

	// TODO: needs more validation

	return nil
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        FlowSet ID             |          Length               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (h *SetHeader) unmarshal(r *reader.Reader) error {
	var err error

	if h.FlowSetID, err = r.Uint16(); err != nil {
		return err
	}

	if h.Length, err = r.Uint16(); err != nil {
		return err
	}

	return nil
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Template ID            |         Field Count           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (t *TemplateHeader) unmarshal(r *reader.Reader) error {
	var err error

	if t.TemplateID, err = r.Uint16(); err != nil {
		return err
	}

	if t.FieldCount, err = r.Uint16(); err != nil {
		return err
	}

	return nil
}

func (t *TemplateHeader) unmarshalOpts(r *reader.Reader) error {
	var err error

	if t.TemplateID, err = r.Uint16(); err != nil {
		return err
	}

	if t.OptionScopeLen, err = r.Uint16(); err != nil {
		return err
	}

	if t.OptionLen, err = r.Uint16(); err != nil {
		return err
	}

	return nil
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Field Type             |         Field Length          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (f *TemplateFieldSpecifier) unmarshal(r *reader.Reader) error {
	var err error

	if f.ElementID, err = r.Uint16(); err != nil {
		return err
	}

	if f.Length, err = r.Uint16(); err != nil {
		return err
	}

	return nil
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Template ID 256          |         Field Count           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Field Type 1           |         Field Length 1        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Field Type 2           |         Field Length 2        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             ...               |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Field Type N           |         Field Length N        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (tr *TemplateRecord) unmarshal(r *reader.Reader) {
	var (
		th = TemplateHeader{}
		tf = TemplateFieldSpecifier{}
	)

	th.unmarshal(r)
	tr.TemplateID = th.TemplateID
	tr.FieldCount = th.FieldCount

	for i := th.FieldCount; i > 0; i-- {
		tf.unmarshal(r)
		tr.FieldSpecifiers = append(tr.FieldSpecifiers, tf)
	}
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       FlowSet ID = 1          |          Length               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Template ID           |      Option Scope Length      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Option Length          |       Scope 1 Field Type      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Scope 1 Field Length      |               ...             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Scope N Field Length      |      Option 1 Field Type      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Option 1 Field Length     |             ...               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Option M Field Length     |           Padding             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (tr *TemplateRecord) unmarshalOpts(r *reader.Reader) {
	var (
		th = TemplateHeader{}
		tf = TemplateFieldSpecifier{}
	)

	th.unmarshalOpts(r)
	tr.TemplateID = th.TemplateID

	for i := th.OptionScopeLen / 4; i > 0; i-- {
		tf.unmarshal(r)
		tr.ScopeFieldSpecifiers = append(tr.FieldSpecifiers, tf)
	}

	for i := th.OptionLen / 4; i > 0; i-- {
		tf.unmarshal(r)
		tr.FieldSpecifiers = append(tr.FieldSpecifiers, tf)
	}

}

func decodeData(r *reader.Reader, tr TemplateRecord) ([]DecodedField, error) {
	var (
		fields []DecodedField
		err    error
		b      []byte
	)

	for i := 0; i < len(tr.FieldSpecifiers); i++ {
		b, err = r.Read(int(tr.FieldSpecifiers[i].Length))
		if err != nil {
			return nil, err
		}

		m, ok := ipfix.InfoModel[ipfix.ElementKey{
			0,
			tr.FieldSpecifiers[i].ElementID,
		}]

		if !ok {
			return nil, fmt.Errorf("Netflow element key (%d) not exist",
				tr.FieldSpecifiers[i].ElementID)
		}

		fields = append(fields, DecodedField{
			ID:    m.FieldID,
			Value: ipfix.Interpret(&b, m.Type),
		})
	}

	for i := 0; i < len(tr.ScopeFieldSpecifiers); i++ {
		b, err = r.Read(int(tr.ScopeFieldSpecifiers[i].Length))
		if err != nil {
			return nil, err
		}

		m, ok := ipfix.InfoModel[ipfix.ElementKey{
			0,
			tr.ScopeFieldSpecifiers[i].ElementID,
		}]

		if !ok {
			return nil, fmt.Errorf("Netflow element key (%d) not exist (scope)",
				tr.ScopeFieldSpecifiers[i].ElementID)
		}

		fields = append(fields, DecodedField{
			ID:    m.FieldID,
			Value: ipfix.Interpret(&b, m.Type),
		})
	}

	return fields, nil
}

// NewDecoder constructs a decoder
func NewDecoder(raddr net.IP, b []byte) *Decoder {
	return &Decoder{raddr, reader.NewReader(b)}
}

// Decode decodes the Netflow raw data
func (d *Decoder) Decode(mem MemCache) (*Message, error) {
	var (
		nextSet int
		msg     = new(Message)
		err     error
	)

	// Netflow Message Header decoding
	if err = msg.Header.unmarshal(d.reader); err != nil {
		return nil, err
	}
	// Netflow Message Header validation
	if err = msg.Header.validate(); err != nil {
		return nil, err
	}

	// Add source IP address as Agent ID
	msg.AgentID = d.raddr.String()

	for d.reader.Len() > 4 {

		setHeader := new(SetHeader)
		setHeader.unmarshal(d.reader)

		if setHeader.Length < 4 {
			return nil, io.ErrUnexpectedEOF
		}

		switch {
		case setHeader.FlowSetID == 0:
			// Template set
			tr := TemplateRecord{}
			tr.unmarshal(d.reader)
			mem.insert(tr.TemplateID, d.raddr, tr)
		case setHeader.FlowSetID == 1:
			// Option set
			tr := TemplateRecord{}
			tr.unmarshalOpts(d.reader)
			mem.insert(tr.TemplateID, d.raddr, tr)
		case setHeader.FlowSetID >= 4 && setHeader.FlowSetID <= 255:
			// Reserved
		default:
			// data
			tr, ok := mem.retrieve(setHeader.FlowSetID, d.raddr)
			if !ok {
				return msg, fmt.Errorf("%s unknown netflow v9 template id# %d",
					d.raddr.String(),
					setHeader.FlowSetID,
				)
			}

			// data records
			nextSet = d.reader.Len() - int(setHeader.Length) + 4
			for d.reader.Len() > nextSet {
				data, err := decodeData(d.reader, tr)
				if err != nil {
					return msg, err
				}

				msg.DataSets = append(msg.DataSets, data)
			}
		}
	}

	return msg, nil
}
