// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package overwatch defines wire format for the Overwatch policy sink.
package overwatch

import (
	"encoding/binary"
)

// RequestHeaderSize is the size of the request header in bytes.
// Layout:
//
//	0 --------- 16 ---------- 32 ---------- 64 ---------- 96 --+
//	| HeaderSize | MessageType | DroppedCount | RequestID | ... |
//	+---- 16 ----+---- 16 -----+----- 32 -----+---- 32 ---+----+
const RequestHeaderSize = 12

// ResponseSize is the fixed size of a policy response in bytes.
// Layout:
//
//	0 ---------- 32 ---------- 40 --------- 64
//	| RequestID  |   Action    |   Padding   |
//	+---- 32 ----+---- 8 ------+---- 24 -----+
const ResponseSize = 8

// Action represents a policy decision.
type Action uint8

const (
	// ActionAllow permits the syscall to proceed.
	ActionAllow Action = 0
	// ActionBlock rejects the syscall with EPERM.
	ActionBlock Action = 1
	// ActionDefer pauses the container and asks the user.
	ActionDefer Action = 2
)

// RequestHeader extends the remote wire header with a RequestID for
// correlating responses.
type RequestHeader struct {
	HeaderSize   uint16
	MessageType  uint16
	DroppedCount uint32
	RequestID    uint32
}

// MarshalTo writes the header to buf. buf must be at least RequestHeaderSize.
func (h *RequestHeader) MarshalTo(buf []byte) {
	binary.LittleEndian.PutUint16(buf[0:2], h.HeaderSize)
	binary.LittleEndian.PutUint16(buf[2:4], h.MessageType)
	binary.LittleEndian.PutUint32(buf[4:8], h.DroppedCount)
	binary.LittleEndian.PutUint32(buf[8:12], h.RequestID)
}

// Response is the policy decision from the host-side Overwatch engine.
type Response struct {
	RequestID uint32
	Action    Action
}

// UnmarshalResponse parses a response from buf. buf must be at least
// ResponseSize bytes.
func UnmarshalResponse(buf []byte) Response {
	return Response{
		RequestID: binary.LittleEndian.Uint32(buf[0:4]),
		Action:    Action(buf[4]),
	}
}

// MarshalResponse writes a response to buf for the host side to send.
func MarshalResponse(r Response, buf []byte) {
	binary.LittleEndian.PutUint32(buf[0:4], r.RequestID)
	buf[4] = byte(r.Action)
	buf[5] = 0
	buf[6] = 0
	buf[7] = 0
}
