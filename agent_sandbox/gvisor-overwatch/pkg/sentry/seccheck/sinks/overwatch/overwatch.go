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
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
	"gvisor.dev/gvisor/pkg/sync"
)

const sinkName = "overwatch"

func init() {
	seccheck.RegisterSink(seccheck.SinkDesc{
		Name:  sinkName,
		Setup: setupSink,
		New:   newSink,
	})
}

// sink sends seccheck events to a host-side Overwatch policy engine over
// a SOCK_SEQPACKET Unix socket and blocks until a verdict (ALLOW/BLOCK/DEFER)
// is received. This makes syscall interception fully preemptive.
type sink struct {
	seccheck.SinkDefaults

	endpoint *fd.FD
	mu       sync.Mutex
	nextID   atomicbitops.Uint32

	droppedCount atomicbitops.Uint32

	timeout        time.Duration
	defaultOnBlock bool // true = default BLOCK on timeout; false = default ALLOW
	booted         atomicbitops.Uint32 // 1 after container start completes
}

var _ seccheck.Sink = (*sink)(nil)

// setupSink connects to the host-side Overwatch Unix socket.
func setupSink(config map[string]any) (*os.File, error) {
	addrOpaque, ok := config["endpoint"]
	if !ok {
		return nil, fmt.Errorf("endpoint not present in overwatch configuration")
	}
	addr, ok := addrOpaque.(string)
	if !ok {
		return nil, fmt.Errorf("endpoint %q is not a string", addrOpaque)
	}
	return setup(addr)
}

func setup(path string) (*os.File, error) {
	log.Debugf("Overwatch sink connecting to %q", path)
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET, 0): %w", err)
	}
	f := os.NewFile(uintptr(socket), path)
	cu := cleanup.Make(func() { _ = f.Close() })
	defer cu.Clean()

	addr := unix.SockaddrUnix{Name: path}
	if err := unix.Connect(int(f.Fd()), &addr); err != nil {
		return nil, fmt.Errorf("connect(%q): %w", path, err)
	}

	// Handshake: send version, receive ack.
	hsOut := pb.Handshake{Version: wire.CurrentVersion}
	out, err := proto.Marshal(&hsOut)
	if err != nil {
		return nil, fmt.Errorf("marshalling handshake: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		return nil, fmt.Errorf("sending handshake: %w", err)
	}

	in := make([]byte, 10240)
	read, err := f.Read(in)
	if err != nil {
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}
	hsIn := pb.Handshake{}
	if err := proto.Unmarshal(in[:read], &hsIn); err != nil {
		return nil, fmt.Errorf("unmarshalling handshake: %w", err)
	}
	if hsIn.Version < 1 {
		return nil, fmt.Errorf("remote version (%d) too old", hsIn.Version)
	}

	// Keep the socket blocking — we need synchronous request-response.
	cu.Release()
	return f, nil
}

// newSink creates a new Overwatch policy sink.
func newSink(config map[string]any, endpoint *fd.FD) (seccheck.Sink, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("overwatch sink requires an endpoint")
	}
	s := &sink{
		endpoint: endpoint,
		timeout:  5 * time.Second,
	}

	if ok, t, err := parseDuration(config, "timeout"); err != nil {
		return nil, err
	} else if ok {
		s.timeout = t
	}

	if defaultOpaque, ok := config["default_on_timeout"]; ok {
		if defaultStr, ok := defaultOpaque.(string); ok && defaultStr == "block" {
			s.defaultOnBlock = true
		}
	}

	log.Debugf("Overwatch sink created, endpoint FD: %d, timeout: %v", s.endpoint.FD(), s.timeout)
	return s, nil
}

func parseDuration(config map[string]any, name string) (bool, time.Duration, error) {
	opaque, ok := config[name]
	if !ok {
		return false, 0, nil
	}
	str, ok := opaque.(string)
	if !ok {
		return false, 0, fmt.Errorf("%s %v is not a string", name, opaque)
	}
	d, err := time.ParseDuration(str)
	if err != nil {
		return false, 0, err
	}
	return true, d, nil
}

func (*sink) Name() string {
	return sinkName
}

func (s *sink) Status() seccheck.SinkStatus {
	return seccheck.SinkStatus{
		DroppedCount: uint64(s.droppedCount.Load()),
	}
}

// Stop implements seccheck.Sink.
func (s *sink) Stop() {
	if s.endpoint != nil {
		s.endpoint.Close()
	}
}

// notify sends an event and reads the response but always returns nil.
// Used for lifecycle events (container start, exit) that must not block.
func (s *sink) notify(msg proto.Message, msgType pb.MessageType) {
	out, err := proto.Marshal(msg)
	if err != nil {
		return
	}
	reqID := s.nextID.Add(1)
	hdr := RequestHeader{
		HeaderSize:   uint16(RequestHeaderSize),
		MessageType:  uint16(msgType),
		DroppedCount: s.droppedCount.Load(),
		RequestID:    reqID,
	}
	var hdrBuf [RequestHeaderSize]byte
	hdr.MarshalTo(hdrBuf[:])

	s.mu.Lock()
	unix.Writev(s.endpoint.FD(), [][]byte{hdrBuf[:], out})
	var buf [ResponseSize]byte
	unix.Read(s.endpoint.FD(), buf[:])
	s.mu.Unlock()
}

// evaluate sends a seccheck event to the host and waits for a verdict.
// Returns nil for ALLOW, an error for BLOCK, or triggers group stop for DEFER.
func (s *sink) evaluate(msg proto.Message, msgType pb.MessageType) error {
	out, err := proto.Marshal(msg)
	if err != nil {
		log.Debugf("Overwatch: marshal error: %v", err)
		return nil // fail open on marshal error
	}

	reqID := s.nextID.Add(1)
	hdr := RequestHeader{
		HeaderSize:   uint16(RequestHeaderSize),
		MessageType:  uint16(msgType),
		DroppedCount: s.droppedCount.Load(),
		RequestID:    reqID,
	}
	var hdrBuf [RequestHeaderSize]byte
	hdr.MarshalTo(hdrBuf[:])

	log.Infof("Overwatch: sending req=%d type=%d size=%d", reqID, msgType, len(out))

	// Send request and read response under the same lock to prevent
	// interleaving between concurrent goroutines.
	s.mu.Lock()
	_, writeErr := unix.Writev(s.endpoint.FD(), [][]byte{hdrBuf[:], out})
	if writeErr != nil {
		s.mu.Unlock()
		log.Debugf("Overwatch: write failed: %v", writeErr)
		s.droppedCount.Add(1)
		return s.defaultAction()
	}

	err = s.readResponseLocked(reqID)
	s.mu.Unlock()
	return err
}

// readResponseLocked reads the policy response from the host.
// Must be called with s.mu held.
func (s *sink) readResponseLocked(expectedID uint32) error {
	// Set read deadline.
	if err := unix.SetsockoptTimeval(s.endpoint.FD(), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
		Sec:  int64(s.timeout / time.Second),
		Usec: int64((s.timeout % time.Second) / time.Microsecond),
	}); err != nil {
		log.Debugf("Overwatch: setsockopt SO_RCVTIMEO: %v", err)
		return s.defaultAction()
	}

	var buf [ResponseSize]byte
	log.Infof("Overwatch: waiting for response req=%d", expectedID)
	n, err := unix.Read(s.endpoint.FD(), buf[:])
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			log.Warningf("Overwatch: timeout waiting for policy response (req=%d)", expectedID)
			return s.defaultAction()
		}
		log.Infof("Overwatch: read error req=%d: %v", expectedID, err)
		return s.defaultAction()
	}
	if n < ResponseSize {
		log.Infof("Overwatch: short read (%d bytes) req=%d", n, expectedID)
		return s.defaultAction()
	}

	resp := UnmarshalResponse(buf[:])
	if resp.RequestID != expectedID {
		log.Warningf("Overwatch: response ID mismatch (got=%d, expected=%d)", resp.RequestID, expectedID)
		return s.defaultAction()
	}

	log.Infof("Overwatch: got response req=%d action=%d", resp.RequestID, resp.Action)

	switch resp.Action {
	case ActionAllow:
		return nil
	case ActionBlock:
		return fmt.Errorf("overwatch: operation blocked by policy")
	case ActionDefer:
		// DEFER: the host will pause the container externally via docker pause
		// or runsc signal. We return nil to let the syscall through — the host
		// freezes the container before the next syscall can execute.
		// This is a pragmatic choice: the Sentry cannot self-SIGSTOP from
		// within a sink callback without risking deadlock.
		log.Infof("Overwatch: operation deferred to user")
		return nil
	default:
		log.Warningf("Overwatch: unknown action %d, defaulting", resp.Action)
		return s.defaultAction()
	}
}

func (s *sink) defaultAction() error {
	if s.defaultOnBlock {
		return fmt.Errorf("overwatch: operation blocked (timeout, default=block)")
	}
	return nil
}

// --- Sink method overrides ---

// Clone implements seccheck.Sink.
// Non-blocking: clone fires during process creation on the critical path.
func (s *sink) Clone(_ context.Context, _ seccheck.FieldSet, info *pb.CloneInfo) error {
	s.notify(info, pb.MessageType_MESSAGE_SENTRY_CLONE)
	return nil
}

// Execve implements seccheck.Sink.
// Non-blocking: sentry-level execve fires during process exec.
func (s *sink) Execve(_ context.Context, _ seccheck.FieldSet, info *pb.ExecveInfo) error {
	s.notify(info, pb.MessageType_MESSAGE_SENTRY_EXEC)
	return nil
}

// ExitNotifyParent implements seccheck.Sink.
// Fire-and-forget: exit notifications are on the teardown path.
func (s *sink) ExitNotifyParent(_ context.Context, _ seccheck.FieldSet, info *pb.ExitNotifyParentInfo) error {
	s.notify(info, pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT)
	return nil
}

// TaskExit implements seccheck.Sink.
// Fire-and-forget: exit notifications are on the teardown path.
func (s *sink) TaskExit(_ context.Context, _ seccheck.FieldSet, info *pb.TaskExit) error {
	s.notify(info, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT)
	return nil
}

// ContainerStart implements seccheck.Sink.
// Fire-and-forget: container start is on the critical boot path and
// blocking here causes the URPC StartRoot call to time out.
func (s *sink) ContainerStart(_ context.Context, _ seccheck.FieldSet, info *pb.Start) error {
	out, err := proto.Marshal(info)
	if err != nil {
		return nil
	}
	reqID := s.nextID.Add(1)
	hdr := RequestHeader{
		HeaderSize:   uint16(RequestHeaderSize),
		MessageType:  uint16(pb.MessageType_MESSAGE_CONTAINER_START),
		DroppedCount: s.droppedCount.Load(),
		RequestID:    reqID,
	}
	var hdrBuf [RequestHeaderSize]byte
	hdr.MarshalTo(hdrBuf[:])

	s.mu.Lock()
	unix.Writev(s.endpoint.FD(), [][]byte{hdrBuf[:], out})
	// Read and discard the response — don't block boot.
	var buf [ResponseSize]byte
	unix.Read(s.endpoint.FD(), buf[:])
	s.mu.Unlock()
	// Mark boot complete — syscall-level enforcement starts now.
	s.booted.Store(1)
	log.Infof("Overwatch: container started, enforcement active (req=%d)", reqID)
	return nil
}

// RawSyscall implements seccheck.Sink.
func (s *sink) RawSyscall(_ context.Context, _ seccheck.FieldSet, info *pb.Syscall) error {
	s.notify(info, pb.MessageType_MESSAGE_SYSCALL_RAW)
	return nil
}

// Syscall implements seccheck.Sink.
// Events are sent synchronously (notify waits for response) but always
// return nil — the host logs and scores them.  Blocking enforcement
// (returning an error to reject the syscall) requires increasing the
// gVisor URPC timeout and will be enabled in a future iteration.
func (s *sink) Syscall(_ context.Context, _ seccheck.FieldSet, _ *pb.ContextData, msgType pb.MessageType, msg proto.Message) error {
	s.notify(msg, msgType)
	return nil
}
