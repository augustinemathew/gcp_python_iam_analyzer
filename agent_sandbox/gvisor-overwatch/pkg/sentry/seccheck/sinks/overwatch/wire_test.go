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

package overwatch

import (
	"testing"
)

func TestRequestHeaderRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		hdr  RequestHeader
	}{
		{
			name: "zero values",
			hdr:  RequestHeader{},
		},
		{
			name: "typical request",
			hdr: RequestHeader{
				HeaderSize:   RequestHeaderSize,
				MessageType:  7, // SYSCALL_OPEN
				DroppedCount: 0,
				RequestID:    42,
			},
		},
		{
			name: "max values",
			hdr: RequestHeader{
				HeaderSize:   0xFFFF,
				MessageType:  0xFFFF,
				DroppedCount: 0xFFFFFFFF,
				RequestID:    0xFFFFFFFF,
			},
		},
		{
			name: "with dropped count",
			hdr: RequestHeader{
				HeaderSize:   RequestHeaderSize,
				MessageType:  11, // SYSCALL_CONNECT
				DroppedCount: 5,
				RequestID:    100,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf [RequestHeaderSize]byte
			tc.hdr.MarshalTo(buf[:])

			// Verify individual fields by reading back from the buffer.
			got := RequestHeader{
				HeaderSize:   uint16(buf[0]) | uint16(buf[1])<<8,
				MessageType:  uint16(buf[2]) | uint16(buf[3])<<8,
				DroppedCount: uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24,
				RequestID:    uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24,
			}

			if got != tc.hdr {
				t.Errorf("roundtrip mismatch: got %+v, want %+v", got, tc.hdr)
			}
		})
	}
}

func TestResponseRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		resp Response
	}{
		{
			name: "allow",
			resp: Response{RequestID: 1, Action: ActionAllow},
		},
		{
			name: "block",
			resp: Response{RequestID: 42, Action: ActionBlock},
		},
		{
			name: "defer",
			resp: Response{RequestID: 99, Action: ActionDefer},
		},
		{
			name: "zero request ID",
			resp: Response{RequestID: 0, Action: ActionAllow},
		},
		{
			name: "max request ID",
			resp: Response{RequestID: 0xFFFFFFFF, Action: ActionBlock},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf [ResponseSize]byte
			MarshalResponse(tc.resp, buf[:])
			got := UnmarshalResponse(buf[:])

			if got != tc.resp {
				t.Errorf("roundtrip mismatch: got %+v, want %+v", got, tc.resp)
			}
		})
	}
}

func TestResponsePaddingIsZeroed(t *testing.T) {
	var buf [ResponseSize]byte
	// Fill with garbage first.
	for i := range buf {
		buf[i] = 0xFF
	}

	MarshalResponse(Response{RequestID: 1, Action: ActionAllow}, buf[:])

	// Bytes 5, 6, 7 must be zero (padding).
	for i := 5; i < ResponseSize; i++ {
		if buf[i] != 0 {
			t.Errorf("padding byte %d not zeroed: got %d", i, buf[i])
		}
	}
}

func TestRequestHeaderSize(t *testing.T) {
	if RequestHeaderSize != 12 {
		t.Errorf("RequestHeaderSize = %d, want 12", RequestHeaderSize)
	}
}

func TestResponseSize(t *testing.T) {
	if ResponseSize != 8 {
		t.Errorf("ResponseSize = %d, want 8", ResponseSize)
	}
}

func TestActionConstants(t *testing.T) {
	if ActionAllow != 0 {
		t.Errorf("ActionAllow = %d, want 0", ActionAllow)
	}
	if ActionBlock != 1 {
		t.Errorf("ActionBlock = %d, want 1", ActionBlock)
	}
	if ActionDefer != 2 {
		t.Errorf("ActionDefer = %d, want 2", ActionDefer)
	}
}

// TestWireCompatibility verifies that the Go wire format matches the Python
// side (overwatch_server.py). The Python server uses struct.pack_into with
// little-endian format strings, so we verify the exact byte layout.
func TestWireCompatibility(t *testing.T) {
	// Request: marshal a known header and check exact bytes.
	hdr := RequestHeader{
		HeaderSize:  12,
		MessageType: 7, // SYSCALL_OPEN
		RequestID:   1,
	}
	var reqBuf [RequestHeaderSize]byte
	hdr.MarshalTo(reqBuf[:])

	// HeaderSize=12 -> 0x0C, 0x00 (LE uint16)
	// MessageType=7 -> 0x07, 0x00 (LE uint16)
	// DroppedCount=0 -> 0x00, 0x00, 0x00, 0x00 (LE uint32)
	// RequestID=1  -> 0x01, 0x00, 0x00, 0x00 (LE uint32)
	want := [RequestHeaderSize]byte{0x0C, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if reqBuf != want {
		t.Errorf("request bytes:\n  got  %v\n  want %v", reqBuf, want)
	}

	// Response: marshal a known response and check exact bytes.
	resp := Response{RequestID: 1, Action: ActionBlock}
	var respBuf [ResponseSize]byte
	MarshalResponse(resp, respBuf[:])

	// RequestID=1 -> 0x01, 0x00, 0x00, 0x00 (LE uint32)
	// Action=1    -> 0x01
	// Padding     -> 0x00, 0x00, 0x00
	wantResp := [ResponseSize]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if respBuf != wantResp {
		t.Errorf("response bytes:\n  got  %v\n  want %v", respBuf, wantResp)
	}
}
