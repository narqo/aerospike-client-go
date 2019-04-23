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
	"reflect"
	"time"

	. "github.com/aerospike/aerospike-client-go/logger"

	. "github.com/aerospike/aerospike-client-go/types"
	Buffer "github.com/aerospike/aerospike-client-go/utils/buffer"
)

type readCommandLike interface {
	command

	handleWriteKeyNotFoundError(ResultCode) error
}

type readCommand struct {
	singleCommand

	policy   *BasePolicy
	binNames []string
	record   *Record

	// pointer to the object that's going to be unmarshalled
	object *reflect.Value

	target interface{}

	replicaSequence int
}

// this method uses reflection.
// Will not be set if performance flag is passed for the build.
var objectParser func(
	cmd *readCommand,
	opCount int,
	fieldCount int,
	generation uint32,
	expiration uint32,
) error

func newReadCommand(cluster *Cluster, policy *BasePolicy, key *Key, binNames []string) readCommand {
	return readCommand{
		singleCommand: newSingleCommand(cluster, key),
		binNames:      binNames,
		policy:        policy,
	}
}

func (cmd *readCommand) getPolicy(ifc command) Policy {
	return cmd.policy
}

func (cmd *readCommand) writeBuffer(ifc command) error {
	return cmd.setRead(cmd.policy, cmd.key, cmd.binNames)
}

func (cmd *readCommand) getNode(ifc command) (*Node, error) {
	return cmd.cluster.getReadNode(&cmd.partition, cmd.policy.ReplicaPolicy, &cmd.replicaSequence)
}

type Decoder struct {
	dataBuffer   []byte
	cursorBuffer []byte
	opCursor     int
	opCount      int
	start        int
	offset       int
}

func (dec *Decoder) Next() (name string, ok bool) {
	dec.start = dec.offset
	ok = dec.opCursor < dec.opCount
	dec.opCursor++

	nameSize := int(dec.dataBuffer[dec.offset+7])
	name = string(dec.dataBuffer[dec.offset+8 : dec.offset+8+nameSize]) // TODO: don't copy, use unsafe_string

	dec.offset += 8 + nameSize

	return name, ok
}

func (dec *Decoder) read() {
	opSize := int(Buffer.BytesToUint32(dec.dataBuffer, dec.start))
	//particleType := int(dec.dataBuffer[dec.start+5]) // type of data to follow
	nameSize := int(dec.dataBuffer[dec.start+7])
	length := opSize - (4 + nameSize)
	dec.cursorBuffer = dec.dataBuffer[dec.offset : dec.offset+length]
	dec.offset += length
}

func (dec *Decoder) Int() (v int64) {
	dec.read()
	return Buffer.VarBytesToInt64(dec.cursorBuffer, 0, len(dec.cursorBuffer))
}

func (dec *Decoder) String() string {
	dec.read()
	return string(dec.cursorBuffer)
}

func (dec *Decoder) Strings() []string {
	panic("not implemented")
}

type BinsDecoder interface {
	DecodeBins(dec *Decoder) error
}

type AeroTracker struct {
	AppToken    string
	ParentToken string // empty for root trackers
	Token       string
	Label       string // part of tracker name, used as link if no external ID available
	ExternalId  string // optional, if set should be used as link from parent
	PartnerId   string
	Level       int // 1..4
	ChildCount  int // how many child trackers does this tracker have

	// for debugging
	ParentTokens   []string  // all parent tokens (up to 3)
	ParentLabels   []string  // initial parent labels from when this tracker was created, as we never update these (up to 3)
	Log            []string  // textual representation of changes to this tracker, with timestamps
	LabelUpdatedAt time.Time // last time tracker was relabeled

	// aerospike generation to see how often we overwrite records
	generation int
}

func (at *AeroTracker) DecodeBins(dec *Decoder) error {
	var (
		name string
		ok   = true
	)
	for ok {
		name, ok = dec.Next()
		switch name {
		case "appToken":
			at.AppToken = dec.String()
		case "tokenP":
			at.ParentToken = dec.String()

		case "parentLs":
			at.ParentTokens = dec.Strings()

		case "gen":
			at.generation = dec.Int()
		}
	}
	return nil
}

func (cmd *readCommand) parseResult(ifc command, conn *Connection) error {
	// Read header.
	_, err := conn.Read(cmd.dataBuffer, int(_MSG_TOTAL_HEADER_SIZE))
	if err != nil {
		Logger.Debug("Connection error reading data for ReadCommand: %s", err.Error())
		return err
	}

	// A number of these are commented out because we just don't care enough to read
	// that section of the header. If we do care, uncomment and check!
	sz := Buffer.BytesToInt64(cmd.dataBuffer, 0)

	// Validate header to make sure we are at the beginning of a message
	if err := cmd.validateHeader(sz); err != nil {
		return err
	}

	headerLength := int(cmd.dataBuffer[8])
	resultCode := ResultCode(cmd.dataBuffer[13] & 0xFF)
	generation := Buffer.BytesToUint32(cmd.dataBuffer, 14)
	expiration := TTL(Buffer.BytesToUint32(cmd.dataBuffer, 18))
	fieldCount := int(Buffer.BytesToUint16(cmd.dataBuffer, 26)) // almost certainly 0
	opCount := int(Buffer.BytesToUint16(cmd.dataBuffer, 28))
	receiveSize := int((sz & 0xFFFFFFFFFFFF) - int64(headerLength))

	// Read remaining message bytes.
	if receiveSize > 0 {
		if err = cmd.sizeBufferSz(receiveSize); err != nil {
			return err
		}
		_, err = conn.Read(cmd.dataBuffer, receiveSize)
		if err != nil {
			Logger.Debug("Connection error reading data for ReadCommand: %s", err.Error())
			return err
		}

	}

	if resultCode != 0 {
		if resultCode == KEY_NOT_FOUND_ERROR && cmd.object == nil {
			if rcmd, ok := ifc.(readCommandLike); ok {
				return rcmd.handleWriteKeyNotFoundError(resultCode)
			}
			return nil
		}

		if resultCode == UDF_BAD_RESPONSE {
			cmd.record, _ = cmd.parseRecord(ifc, opCount, fieldCount, generation, expiration)
			err := cmd.handleUdfError(resultCode)
			Logger.Warn("UDF execution error: " + err.Error())
			return err
		}

		return NewAerospikeError(resultCode)
	}

	if cmd.object == nil {
		if opCount == 0 {
			// data Bin was not returned
			cmd.record = newRecord(cmd.node, cmd.key, nil, generation, expiration)
			return nil
		}

		cmd.record, err = cmd.parseRecord(ifc, opCount, fieldCount, generation, expiration)
		if err != nil {
			return err
		}
	} else if objectParser != nil {
		if err := objectParser(cmd, opCount, fieldCount, generation, expiration); err != nil {
			return err
		}
	}

	return nil
}

func (cmd *readCommand) handleUdfError(resultCode ResultCode) error {
	if ret, exists := cmd.record.Bins["FAILURE"]; exists {
		return NewAerospikeError(resultCode, ret.(string))
	}
	return NewAerospikeError(resultCode)
}

func (cmd *readCommand) parseRecord(
	ifc command,
	opCount int,
	fieldCount int,
	generation uint32,
	expiration uint32,
) (*Record, error) {
	var bins BinMap
	receiveOffset := 0

	type opList []interface{}
	_, isOperate := ifc.(*operateCommand)
	var binNamesSet []string

	// There can be fields in the response (setname etc).
	// But for now, ignore them. Expose them to the API if needed in the future.
	// Logger.Debug("field count: %d, databuffer: %v", fieldCount, cmd.dataBuffer)
	if fieldCount > 0 {
		// Just skip over all the fields
		for i := 0; i < fieldCount; i++ {
			// Logger.Debug("%d", receiveOffset)
			fieldSize := int(Buffer.BytesToUint32(cmd.dataBuffer, receiveOffset))
			receiveOffset += (4 + fieldSize)
		}
	}

	if cmd.target != nil {
		dec := Decoder{
			dataBuffer: cmd.dataBuffer,
			offset:     receiveOffset,
		}
		err := cmd.target.(BinsDecoder).DecodeBins(&dec)
		return nil, err
	}

	if opCount > 0 {
		bins = make(BinMap, opCount)
	}

	for i := 0; i < opCount; i++ {
		opSize := int(Buffer.BytesToUint32(cmd.dataBuffer, receiveOffset))
		particleType := int(cmd.dataBuffer[receiveOffset+5])
		nameSize := int(cmd.dataBuffer[receiveOffset+7])
		name := string(cmd.dataBuffer[receiveOffset+8 : receiveOffset+8+nameSize])
		receiveOffset += 4 + 4 + nameSize

		particleBytesSize := opSize - (4 + nameSize)
		value, _ := bytesToParticle(particleType, cmd.dataBuffer, receiveOffset, particleBytesSize)
		receiveOffset += particleBytesSize

		if bins == nil {
			bins = make(BinMap, opCount)
		}

		if isOperate {
			// for operate list command results
			if prev, exists := bins[name]; exists {
				if res, ok := prev.(opList); ok {
					// List already exists.  Add to it.
					bins[name] = append(res, value)
				} else {
					// Make a list to store all values.
					bins[name] = opList{prev, value}
					binNamesSet = append(binNamesSet, name)
				}
			} else {
				bins[name] = value
			}
		} else {
			bins[name] = value
		}
	}

	if isOperate {
		for i := range binNamesSet {
			bins[binNamesSet[i]] = []interface{}(bins[binNamesSet[i]].(opList))
		}
	}

	return newRecord(cmd.node, cmd.key, bins, generation, expiration), nil
}

func (cmd *readCommand) GetRecord() *Record {
	return cmd.record
}

func (cmd *readCommand) Execute() error {
	return cmd.execute(cmd, true)
}

func (cmd *readCommand) handleWriteKeyNotFoundError(resultCode ResultCode) error {
	// command returns no error if key was not found
	return nil
}
