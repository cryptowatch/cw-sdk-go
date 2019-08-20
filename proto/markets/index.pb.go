// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: markets/index.proto

package ProtobufMarkets

/*
	NOTE: While a lot of these types have been expanded to indices, to prevent
	breaking clients by changing protbuf message types and names
	we'll just leave the package as ProtobufMarkets
*/

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Index represents a index metric which may be produced on cryptowatch
// or belong to an exchange
type Index struct {
	Id                   uint64   `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Symbol               string   `protobuf:"bytes,2,opt,name=symbol,proto3" json:"symbol,omitempty"`
	IndexType            string   `protobuf:"bytes,3,opt,name=indexType,proto3" json:"indexType,omitempty"`
	CwIndex              bool     `protobuf:"varint,4,opt,name=cwIndex,proto3" json:"cwIndex,omitempty"`
	ExchangeId           uint64   `protobuf:"varint,5,opt,name=exchangeId,proto3" json:"exchangeId,omitempty"`
	InstrumentId         uint64   `protobuf:"varint,6,opt,name=instrumentId,proto3" json:"instrumentId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Index) Reset()         { *m = Index{} }
func (m *Index) String() string { return proto.CompactTextString(m) }
func (*Index) ProtoMessage()    {}
func (*Index) Descriptor() ([]byte, []int) {
	return fileDescriptor_index_495ff0f94327cf88, []int{0}
}
func (m *Index) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Index) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Index.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Index) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Index.Merge(dst, src)
}
func (m *Index) XXX_Size() int {
	return m.Size()
}
func (m *Index) XXX_DiscardUnknown() {
	xxx_messageInfo_Index.DiscardUnknown(m)
}

var xxx_messageInfo_Index proto.InternalMessageInfo

func (m *Index) GetId() uint64 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *Index) GetSymbol() string {
	if m != nil {
		return m.Symbol
	}
	return ""
}

func (m *Index) GetIndexType() string {
	if m != nil {
		return m.IndexType
	}
	return ""
}

func (m *Index) GetCwIndex() bool {
	if m != nil {
		return m.CwIndex
	}
	return false
}

func (m *Index) GetExchangeId() uint64 {
	if m != nil {
		return m.ExchangeId
	}
	return 0
}

func (m *Index) GetInstrumentId() uint64 {
	if m != nil {
		return m.InstrumentId
	}
	return 0
}

type IndexUpdateMessage struct {
	Index *Index `protobuf:"bytes,1,opt,name=index,proto3" json:"index,omitempty"`
	// Types that are valid to be assigned to Update:
	//	*IndexUpdateMessage_TickerUpdate
	//	*IndexUpdateMessage_IntervalsUpdate
	//	*IndexUpdateMessage_SummaryUpdate
	//	*IndexUpdateMessage_SparklineUpdate
	Update               isIndexUpdateMessage_Update `protobuf_oneof:"Update"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *IndexUpdateMessage) Reset()         { *m = IndexUpdateMessage{} }
func (m *IndexUpdateMessage) String() string { return proto.CompactTextString(m) }
func (*IndexUpdateMessage) ProtoMessage()    {}
func (*IndexUpdateMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_index_495ff0f94327cf88, []int{1}
}
func (m *IndexUpdateMessage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *IndexUpdateMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_IndexUpdateMessage.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *IndexUpdateMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IndexUpdateMessage.Merge(dst, src)
}
func (m *IndexUpdateMessage) XXX_Size() int {
	return m.Size()
}
func (m *IndexUpdateMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_IndexUpdateMessage.DiscardUnknown(m)
}

var xxx_messageInfo_IndexUpdateMessage proto.InternalMessageInfo

type isIndexUpdateMessage_Update interface {
	isIndexUpdateMessage_Update()
	MarshalTo([]byte) (int, error)
	Size() int
}

type IndexUpdateMessage_TickerUpdate struct {
	TickerUpdate *TickerUpdate `protobuf:"bytes,2,opt,name=tickerUpdate,proto3,oneof"`
}
type IndexUpdateMessage_IntervalsUpdate struct {
	IntervalsUpdate *IntervalsUpdate `protobuf:"bytes,3,opt,name=intervalsUpdate,proto3,oneof"`
}
type IndexUpdateMessage_SummaryUpdate struct {
	SummaryUpdate *SummaryUpdate `protobuf:"bytes,4,opt,name=summaryUpdate,proto3,oneof"`
}
type IndexUpdateMessage_SparklineUpdate struct {
	SparklineUpdate *SparklineUpdate `protobuf:"bytes,5,opt,name=sparklineUpdate,proto3,oneof"`
}

func (*IndexUpdateMessage_TickerUpdate) isIndexUpdateMessage_Update()    {}
func (*IndexUpdateMessage_IntervalsUpdate) isIndexUpdateMessage_Update() {}
func (*IndexUpdateMessage_SummaryUpdate) isIndexUpdateMessage_Update()   {}
func (*IndexUpdateMessage_SparklineUpdate) isIndexUpdateMessage_Update() {}

func (m *IndexUpdateMessage) GetUpdate() isIndexUpdateMessage_Update {
	if m != nil {
		return m.Update
	}
	return nil
}

func (m *IndexUpdateMessage) GetIndex() *Index {
	if m != nil {
		return m.Index
	}
	return nil
}

func (m *IndexUpdateMessage) GetTickerUpdate() *TickerUpdate {
	if x, ok := m.GetUpdate().(*IndexUpdateMessage_TickerUpdate); ok {
		return x.TickerUpdate
	}
	return nil
}

func (m *IndexUpdateMessage) GetIntervalsUpdate() *IntervalsUpdate {
	if x, ok := m.GetUpdate().(*IndexUpdateMessage_IntervalsUpdate); ok {
		return x.IntervalsUpdate
	}
	return nil
}

func (m *IndexUpdateMessage) GetSummaryUpdate() *SummaryUpdate {
	if x, ok := m.GetUpdate().(*IndexUpdateMessage_SummaryUpdate); ok {
		return x.SummaryUpdate
	}
	return nil
}

func (m *IndexUpdateMessage) GetSparklineUpdate() *SparklineUpdate {
	if x, ok := m.GetUpdate().(*IndexUpdateMessage_SparklineUpdate); ok {
		return x.SparklineUpdate
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*IndexUpdateMessage) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _IndexUpdateMessage_OneofMarshaler, _IndexUpdateMessage_OneofUnmarshaler, _IndexUpdateMessage_OneofSizer, []interface{}{
		(*IndexUpdateMessage_TickerUpdate)(nil),
		(*IndexUpdateMessage_IntervalsUpdate)(nil),
		(*IndexUpdateMessage_SummaryUpdate)(nil),
		(*IndexUpdateMessage_SparklineUpdate)(nil),
	}
}

func _IndexUpdateMessage_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*IndexUpdateMessage)
	// Update
	switch x := m.Update.(type) {
	case *IndexUpdateMessage_TickerUpdate:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.TickerUpdate); err != nil {
			return err
		}
	case *IndexUpdateMessage_IntervalsUpdate:
		_ = b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.IntervalsUpdate); err != nil {
			return err
		}
	case *IndexUpdateMessage_SummaryUpdate:
		_ = b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.SummaryUpdate); err != nil {
			return err
		}
	case *IndexUpdateMessage_SparklineUpdate:
		_ = b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.SparklineUpdate); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("IndexUpdateMessage.Update has unexpected type %T", x)
	}
	return nil
}

func _IndexUpdateMessage_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*IndexUpdateMessage)
	switch tag {
	case 2: // Update.tickerUpdate
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(TickerUpdate)
		err := b.DecodeMessage(msg)
		m.Update = &IndexUpdateMessage_TickerUpdate{msg}
		return true, err
	case 3: // Update.intervalsUpdate
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(IntervalsUpdate)
		err := b.DecodeMessage(msg)
		m.Update = &IndexUpdateMessage_IntervalsUpdate{msg}
		return true, err
	case 4: // Update.summaryUpdate
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(SummaryUpdate)
		err := b.DecodeMessage(msg)
		m.Update = &IndexUpdateMessage_SummaryUpdate{msg}
		return true, err
	case 5: // Update.sparklineUpdate
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(SparklineUpdate)
		err := b.DecodeMessage(msg)
		m.Update = &IndexUpdateMessage_SparklineUpdate{msg}
		return true, err
	default:
		return false, nil
	}
}

func _IndexUpdateMessage_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*IndexUpdateMessage)
	// Update
	switch x := m.Update.(type) {
	case *IndexUpdateMessage_TickerUpdate:
		s := proto.Size(x.TickerUpdate)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *IndexUpdateMessage_IntervalsUpdate:
		s := proto.Size(x.IntervalsUpdate)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *IndexUpdateMessage_SummaryUpdate:
		s := proto.Size(x.SummaryUpdate)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *IndexUpdateMessage_SparklineUpdate:
		s := proto.Size(x.SparklineUpdate)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// TickerUpdate is just a single ticker message
type TickerUpdate struct {
	Tickers              []*Ticker `protobuf:"bytes,1,rep,name=tickers,proto3" json:"tickers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *TickerUpdate) Reset()         { *m = TickerUpdate{} }
func (m *TickerUpdate) String() string { return proto.CompactTextString(m) }
func (*TickerUpdate) ProtoMessage()    {}
func (*TickerUpdate) Descriptor() ([]byte, []int) {
	return fileDescriptor_index_495ff0f94327cf88, []int{2}
}
func (m *TickerUpdate) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TickerUpdate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TickerUpdate.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *TickerUpdate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TickerUpdate.Merge(dst, src)
}
func (m *TickerUpdate) XXX_Size() int {
	return m.Size()
}
func (m *TickerUpdate) XXX_DiscardUnknown() {
	xxx_messageInfo_TickerUpdate.DiscardUnknown(m)
}

var xxx_messageInfo_TickerUpdate proto.InternalMessageInfo

func (m *TickerUpdate) GetTickers() []*Ticker {
	if m != nil {
		return m.Tickers
	}
	return nil
}

// Ticker is just a single update instance in TickerUpdate
type Ticker struct {
	Value     string `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Timestamp int64  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// Just to keep consistency with Trade
	// this will also be called timestampNano
	TimestampNano        int64    `protobuf:"varint,3,opt,name=timestampNano,proto3" json:"timestampNano,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ticker) Reset()         { *m = Ticker{} }
func (m *Ticker) String() string { return proto.CompactTextString(m) }
func (*Ticker) ProtoMessage()    {}
func (*Ticker) Descriptor() ([]byte, []int) {
	return fileDescriptor_index_495ff0f94327cf88, []int{3}
}
func (m *Ticker) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Ticker) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Ticker.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Ticker) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ticker.Merge(dst, src)
}
func (m *Ticker) XXX_Size() int {
	return m.Size()
}
func (m *Ticker) XXX_DiscardUnknown() {
	xxx_messageInfo_Ticker.DiscardUnknown(m)
}

var xxx_messageInfo_Ticker proto.InternalMessageInfo

func (m *Ticker) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func (m *Ticker) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *Ticker) GetTimestampNano() int64 {
	if m != nil {
		return m.TimestampNano
	}
	return 0
}

func init() {
	proto.RegisterType((*Index)(nil), "ProtobufMarkets.Index")
	proto.RegisterType((*IndexUpdateMessage)(nil), "ProtobufMarkets.IndexUpdateMessage")
	proto.RegisterType((*TickerUpdate)(nil), "ProtobufMarkets.TickerUpdate")
	proto.RegisterType((*Ticker)(nil), "ProtobufMarkets.Ticker")
}
func (m *Index) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Index) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Id != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.Id))
	}
	if len(m.Symbol) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintIndex(dAtA, i, uint64(len(m.Symbol)))
		i += copy(dAtA[i:], m.Symbol)
	}
	if len(m.IndexType) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintIndex(dAtA, i, uint64(len(m.IndexType)))
		i += copy(dAtA[i:], m.IndexType)
	}
	if m.CwIndex {
		dAtA[i] = 0x20
		i++
		if m.CwIndex {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	if m.ExchangeId != 0 {
		dAtA[i] = 0x28
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.ExchangeId))
	}
	if m.InstrumentId != 0 {
		dAtA[i] = 0x30
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.InstrumentId))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *IndexUpdateMessage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *IndexUpdateMessage) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Index != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.Index.Size()))
		n1, err := m.Index.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.Update != nil {
		nn2, err := m.Update.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += nn2
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *IndexUpdateMessage_TickerUpdate) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.TickerUpdate != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.TickerUpdate.Size()))
		n3, err := m.TickerUpdate.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	return i, nil
}
func (m *IndexUpdateMessage_IntervalsUpdate) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.IntervalsUpdate != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.IntervalsUpdate.Size()))
		n4, err := m.IntervalsUpdate.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	return i, nil
}
func (m *IndexUpdateMessage_SummaryUpdate) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.SummaryUpdate != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.SummaryUpdate.Size()))
		n5, err := m.SummaryUpdate.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n5
	}
	return i, nil
}
func (m *IndexUpdateMessage_SparklineUpdate) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.SparklineUpdate != nil {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.SparklineUpdate.Size()))
		n6, err := m.SparklineUpdate.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n6
	}
	return i, nil
}
func (m *TickerUpdate) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TickerUpdate) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Tickers) > 0 {
		for _, msg := range m.Tickers {
			dAtA[i] = 0xa
			i++
			i = encodeVarintIndex(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *Ticker) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Ticker) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Value) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintIndex(dAtA, i, uint64(len(m.Value)))
		i += copy(dAtA[i:], m.Value)
	}
	if m.Timestamp != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.Timestamp))
	}
	if m.TimestampNano != 0 {
		dAtA[i] = 0x18
		i++
		i = encodeVarintIndex(dAtA, i, uint64(m.TimestampNano))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintIndex(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Index) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != 0 {
		n += 1 + sovIndex(uint64(m.Id))
	}
	l = len(m.Symbol)
	if l > 0 {
		n += 1 + l + sovIndex(uint64(l))
	}
	l = len(m.IndexType)
	if l > 0 {
		n += 1 + l + sovIndex(uint64(l))
	}
	if m.CwIndex {
		n += 2
	}
	if m.ExchangeId != 0 {
		n += 1 + sovIndex(uint64(m.ExchangeId))
	}
	if m.InstrumentId != 0 {
		n += 1 + sovIndex(uint64(m.InstrumentId))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *IndexUpdateMessage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Index != nil {
		l = m.Index.Size()
		n += 1 + l + sovIndex(uint64(l))
	}
	if m.Update != nil {
		n += m.Update.Size()
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *IndexUpdateMessage_TickerUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.TickerUpdate != nil {
		l = m.TickerUpdate.Size()
		n += 1 + l + sovIndex(uint64(l))
	}
	return n
}
func (m *IndexUpdateMessage_IntervalsUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.IntervalsUpdate != nil {
		l = m.IntervalsUpdate.Size()
		n += 1 + l + sovIndex(uint64(l))
	}
	return n
}
func (m *IndexUpdateMessage_SummaryUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.SummaryUpdate != nil {
		l = m.SummaryUpdate.Size()
		n += 1 + l + sovIndex(uint64(l))
	}
	return n
}
func (m *IndexUpdateMessage_SparklineUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.SparklineUpdate != nil {
		l = m.SparklineUpdate.Size()
		n += 1 + l + sovIndex(uint64(l))
	}
	return n
}
func (m *TickerUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Tickers) > 0 {
		for _, e := range m.Tickers {
			l = e.Size()
			n += 1 + l + sovIndex(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Ticker) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Value)
	if l > 0 {
		n += 1 + l + sovIndex(uint64(l))
	}
	if m.Timestamp != 0 {
		n += 1 + sovIndex(uint64(m.Timestamp))
	}
	if m.TimestampNano != 0 {
		n += 1 + sovIndex(uint64(m.TimestampNano))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovIndex(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozIndex(x uint64) (n int) {
	return sovIndex(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Index) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowIndex
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Index: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Index: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			m.Id = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Id |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Symbol", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Symbol = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IndexType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.IndexType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field CwIndex", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.CwIndex = bool(v != 0)
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExchangeId", wireType)
			}
			m.ExchangeId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ExchangeId |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field InstrumentId", wireType)
			}
			m.InstrumentId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.InstrumentId |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipIndex(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthIndex
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *IndexUpdateMessage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowIndex
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: IndexUpdateMessage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: IndexUpdateMessage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Index", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Index == nil {
				m.Index = &Index{}
			}
			if err := m.Index.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TickerUpdate", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &TickerUpdate{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Update = &IndexUpdateMessage_TickerUpdate{v}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IntervalsUpdate", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &IntervalsUpdate{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Update = &IndexUpdateMessage_IntervalsUpdate{v}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SummaryUpdate", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &SummaryUpdate{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Update = &IndexUpdateMessage_SummaryUpdate{v}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SparklineUpdate", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &SparklineUpdate{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Update = &IndexUpdateMessage_SparklineUpdate{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipIndex(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthIndex
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *TickerUpdate) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowIndex
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: TickerUpdate: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TickerUpdate: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Tickers", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Tickers = append(m.Tickers, &Ticker{})
			if err := m.Tickers[len(m.Tickers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipIndex(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthIndex
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Ticker) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowIndex
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Ticker: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Ticker: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthIndex
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Value = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			m.Timestamp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Timestamp |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TimestampNano", wireType)
			}
			m.TimestampNano = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TimestampNano |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipIndex(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthIndex
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipIndex(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowIndex
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowIndex
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthIndex
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowIndex
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipIndex(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthIndex = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowIndex   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("markets/index.proto", fileDescriptor_index_495ff0f94327cf88) }

var fileDescriptor_index_495ff0f94327cf88 = []byte{
	// 425 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x52, 0xdd, 0x6e, 0xd3, 0x30,
	0x14, 0xae, 0x9b, 0x26, 0x5b, 0x4f, 0x3b, 0x86, 0xcc, 0x34, 0x2c, 0x04, 0x51, 0x14, 0x71, 0x91,
	0x0b, 0x54, 0x44, 0x79, 0x02, 0x86, 0x84, 0x5a, 0x89, 0x21, 0xe4, 0x8d, 0x07, 0x70, 0x1a, 0x33,
	0xac, 0xe6, 0x4f, 0xb1, 0x33, 0xd6, 0x37, 0xe1, 0x1d, 0x78, 0x11, 0x2e, 0x79, 0x04, 0x54, 0x9e,
	0x81, 0x7b, 0x94, 0xe3, 0x94, 0x25, 0x1d, 0xbb, 0xb2, 0xcf, 0xe7, 0xef, 0xfb, 0xce, 0xe7, 0x63,
	0xc3, 0xa3, 0x4c, 0x54, 0x6b, 0x69, 0xf4, 0x4b, 0x95, 0x27, 0xf2, 0x66, 0x56, 0x56, 0x85, 0x29,
	0xe8, 0xf1, 0xc7, 0x66, 0x89, 0xeb, 0xcf, 0xe7, 0xf6, 0xf0, 0xc9, 0xc9, 0x8e, 0x65, 0x57, 0x4b,
	0x0b, 0xbf, 0x13, 0x70, 0x97, 0x8d, 0x8c, 0x3e, 0x80, 0xa1, 0x4a, 0x18, 0x09, 0x48, 0x34, 0xe2,
	0x43, 0x95, 0xd0, 0x53, 0xf0, 0xf4, 0x26, 0x8b, 0x8b, 0x94, 0x0d, 0x03, 0x12, 0x8d, 0x79, 0x5b,
	0xd1, 0xa7, 0x30, 0xc6, 0x3e, 0x97, 0x9b, 0x52, 0x32, 0x07, 0x8f, 0x6e, 0x01, 0xca, 0xe0, 0x60,
	0xf5, 0x15, 0x0d, 0xd9, 0x28, 0x20, 0xd1, 0x21, 0xdf, 0x95, 0xd4, 0x07, 0x90, 0x37, 0xab, 0x2f,
	0x22, 0xbf, 0x92, 0xcb, 0x84, 0xb9, 0xd8, 0xa7, 0x83, 0xd0, 0x10, 0xa6, 0x2a, 0xd7, 0xa6, 0xaa,
	0x33, 0x99, 0x9b, 0x65, 0xc2, 0x3c, 0x64, 0xf4, 0xb0, 0xf0, 0xcf, 0x10, 0x28, 0xba, 0x7d, 0x2a,
	0x13, 0x61, 0xe4, 0xb9, 0xd4, 0x5a, 0x5c, 0x49, 0xfa, 0x02, 0x5c, 0x4c, 0x80, 0xe9, 0x27, 0xf3,
	0xd3, 0xd9, 0xde, 0xdd, 0x67, 0xa8, 0xe1, 0x96, 0x44, 0xdf, 0xc2, 0xd4, 0xa8, 0xd5, 0x5a, 0x56,
	0xd6, 0x04, 0xaf, 0x37, 0x99, 0x3f, 0xbb, 0x23, 0xba, 0xec, 0x90, 0x16, 0x03, 0xde, 0x13, 0xd1,
	0xf7, 0x70, 0xac, 0x72, 0x23, 0xab, 0x6b, 0x91, 0xea, 0xd6, 0xc7, 0x41, 0x9f, 0xe0, 0x3f, 0xcd,
	0x7b, 0xbc, 0xc5, 0x80, 0xef, 0x4b, 0xe9, 0x3b, 0x38, 0xd2, 0x75, 0x96, 0x89, 0x6a, 0xd3, 0x7a,
	0x8d, 0xd0, 0xcb, 0xbf, 0xe3, 0x75, 0xd1, 0x65, 0x2d, 0x06, 0xbc, 0x2f, 0x6b, 0x52, 0xe9, 0x52,
	0x54, 0xeb, 0x54, 0xe5, 0xb2, 0x75, 0x72, 0xef, 0x49, 0x75, 0xd1, 0xe7, 0x35, 0xa9, 0xf6, 0xa4,
	0x67, 0x87, 0xe0, 0xd9, 0x5d, 0xf8, 0x06, 0xa6, 0xdd, 0x69, 0xd0, 0x57, 0x70, 0x60, 0xa7, 0xa1,
	0x19, 0x09, 0x9c, 0x68, 0x32, 0x7f, 0x7c, 0xcf, 0xf4, 0xf8, 0x8e, 0x17, 0xc6, 0xe0, 0x59, 0x88,
	0x9e, 0x80, 0x7b, 0x2d, 0xd2, 0x5a, 0xe2, 0x6b, 0x8d, 0xb9, 0x2d, 0x9a, 0x6f, 0x65, 0x54, 0x26,
	0xb5, 0x11, 0x59, 0x89, 0x4f, 0xe2, 0xf0, 0x5b, 0x80, 0x3e, 0x87, 0xa3, 0x7f, 0xc5, 0x07, 0x91,
	0x17, 0x38, 0x6c, 0x87, 0xf7, 0xc1, 0xb3, 0x87, 0x3f, 0xb6, 0x3e, 0xf9, 0xb9, 0xf5, 0xc9, 0xaf,
	0xad, 0x4f, 0xbe, 0xfd, 0xf6, 0x07, 0xb1, 0x87, 0xbf, 0xfc, 0xf5, 0xdf, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x7c, 0x23, 0x44, 0x54, 0x23, 0x03, 0x00, 0x00,
}