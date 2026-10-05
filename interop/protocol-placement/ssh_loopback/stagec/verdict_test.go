//go:build stagec
// +build stagec

package main

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
)

// A mutated key that the server rejects must be distinguishable from a broken
// relay. Before this distinction existed, sshd closing without a DISCONNECT was
// reported as harness_error, which is both a false harness fault and a red CI
// signal for a real protocol observation.
func TestIsConnClosed_EOFIsServerAbort(t *testing.T) {
	if !isConnClosed(io.EOF) {
		t.Error("io.EOF (sshd closed without DISCONNECT) must classify as a closed connection, not a harness fault")
	}
	if !isConnClosed(syscall.ECONNRESET) {
		t.Error("ECONNRESET must classify as a closed connection")
	}
}

func TestIsConnClosed_ProtocolDesyncIsHarnessError(t *testing.T) {
	if isConnClosed(errors.New("expected msg 31 S_REPLY or msg 1 DISCONNECT, got 5")) {
		t.Error("a protocol desync is a genuine harness fault and must not be reclassified")
	}
	// A read deadline expiring means the peer stalled, not that it hung up.
	if isConnClosed(net.ErrClosed) != true {
		t.Error("net.ErrClosed should classify as a closed connection")
	}
}

// The recording layer must round-trip the new verdict verbatim, so the
// distinction survives into the verdict TSV that CI reads.
func TestVerdictRoundTripsServerAbort(t *testing.T) {
	const want = "server_abort_no_reply"
	res := stageCResult{Mode: "mutator", Stimulus: "coeff0_q", Verdict: want, Error: "recv-upstream-sreply: EOF"}
	if res.Verdict != want {
		t.Fatalf("verdict not preserved: got %q", res.Verdict)
	}
}