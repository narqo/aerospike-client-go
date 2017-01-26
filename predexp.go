// Copyright 2013-2017 Aerospike, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aerospike

import (
)

const (
	AS_PREDEXP_AND					uint16 = 1
	AS_PREDEXP_OR					uint16 = 2
	AS_PREDEXP_NOT					uint16 = 3

	AS_PREDEXP_INTEGER_VALUE		uint16 = 10
	AS_PREDEXP_STRING_VALUE			uint16 = 11
	AS_PREDEXP_GEOJSON_VALUE		uint16 = 12

	AS_PREDEXP_INTEGER_BIN			uint16 = 100
	AS_PREDEXP_STRING_BIN			uint16 = 101
	AS_PREDEXP_GEOJSON_BIN			uint16 = 102

	AS_PREDEXP_RECSIZE				uint16 = 150
	AS_PREDEXP_LAST_UPDATE			uint16 = 151
	AS_PREDEXP_VOID_TIME			uint16 = 152

	AS_PREDEXP_INTEGER_EQUAL		uint16 = 200
	AS_PREDEXP_INTEGER_UNEQUAL		uint16 = 201
	AS_PREDEXP_INTEGER_GREATER		uint16 = 202
	AS_PREDEXP_INTEGER_GREATEREQ	uint16 = 203
	AS_PREDEXP_INTEGER_LESS			uint16 = 204
	AS_PREDEXP_INTEGER_LESSEQ		uint16 = 205

	AS_PREDEXP_STRING_EQUAL			uint16 = 210
	AS_PREDEXP_STRING_UNEQUAL		uint16 = 211
	AS_PREDEXP_STRING_REGEX			uint16 = 212

	AS_PREDEXP_GEOJSON_WITHIN		uint16 = 220
	AS_PREDEXP_GEOJSON_CONTAINS		uint16 = 221
)	

// ----------------

type PredExp interface {
	MarshaledSize() int
	Marshal(cmd *baseCommand) error
}

type PredExpBase struct {
}

func (self *PredExpBase) MarshaledSize() int {
	return 2 + 4	// sizeof(TAG) + sizeof(LEN)
}

func (self *PredExpBase) MarshalTL(
	cmd *baseCommand,
	tag uint16,
	len uint32) int {
	return 2 + 4	// sizeof(TAG) + sizeof(LEN)
}

// ---------------- PredExpAnd

type PredExpAnd struct {
	PredExpBase
	nexpr uint16	// number of child expressions
}

func NewPredExpAnd(nexpr uint16) *PredExpAnd {
	return &PredExpAnd{ nexpr: nexpr }
}

func (self *PredExpAnd) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize() + 2
}

func (self *PredExpAnd) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, AS_PREDEXP_AND, 2)
	cmd.WriteUint16(self.nexpr)
	return nil
}

// ---------------- PredExpOr

type PredExpOr struct {
	PredExpBase
	nexpr uint16	// number of child expressions
}

func NewPredExpOr(nexpr uint16) *PredExpOr {
	return &PredExpOr{ nexpr: nexpr }
}

func (self *PredExpOr) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize() + 2
}

func (self *PredExpOr) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, AS_PREDEXP_OR, 2)
	cmd.WriteUint16(self.nexpr)
	return nil
}

// ---------------- PredExpNot

type PredExpNot struct {
	PredExpBase
}

func NewPredExpNot() *PredExpNot {
	return &PredExpNot{ }
}

func (self *PredExpNot) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize()
}

func (self *PredExpNot) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, AS_PREDEXP_NOT, 0)
	return nil
}

// ----------------

type PredExpIntegerValue struct {
	PredExpBase
	val int64
}

func NewPredExpIntegerValue(val int64) *PredExpIntegerValue {
	return &PredExpIntegerValue{ val: val }
}

func (self *PredExpIntegerValue) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize() + 8
}

func (self *PredExpIntegerValue) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, AS_PREDEXP_INTEGER_VALUE, 8)
	cmd.WriteInt64(self.val)
	return nil
}

// ----------------

type PredExpStringValue struct {
	PredExpBase
	val string
}

func NewPredExpStringValue(val string) *PredExpStringValue {
	return &PredExpStringValue{ val: val }
}

func (self *PredExpStringValue) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize() + len(self.val)
}

func (self *PredExpStringValue) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, AS_PREDEXP_STRING_VALUE, uint32(len(self.val)))
	cmd.WriteString(self.val)
	return nil
}

// ----------------

// FIXME - Need GeoJSON here ...

// ----------------

type PredExpBin struct {
	PredExpBase
	name string
	tag uint16	// not marshaled
}

func NewPredExpIntegerBin(name string) *PredExpBin {
	return &PredExpBin{ name: name, tag: AS_PREDEXP_INTEGER_BIN, }
}

func NewPredExpStringBin(name string) *PredExpBin {
	return &PredExpBin{ name: name, tag: AS_PREDEXP_STRING_BIN, }
}

func NewPredExpGeoJSONBin(name string) *PredExpBin {
	return &PredExpBin{ name: name, tag: AS_PREDEXP_GEOJSON_BIN, }
}

func (self *PredExpBin) MarshaledSize() int {
	return self.PredExpBase.MarshaledSize() + 1 + len(self.name)
}

func (self *PredExpBin) Marshal(cmd *baseCommand) error {
	self.MarshalTL(cmd, self.tag, uint32(1 + len(self.name)))
	cmd.WriteByte(uint8(len(self.name)))
	cmd.WriteString(self.name)
	return nil
}

// FIXME - Need to pick up with rest here ...
