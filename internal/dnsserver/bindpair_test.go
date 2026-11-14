package dnsserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

// failingPair binds real loopback listeners but fails the first n TCP binds,
// like a port inside a Windows reserved range (#204). It records the UDP
// addresses asked for.
func failingPair(t *testing.T, n int) (pairListeners, *[]string) {
	t.Helper()
	var asked []string
	lc := &net.ListenConfig{}
	fails := 0
	return pairListeners{
		packet: func(addr string) (net.PacketConn, error) {
			asked = append(asked, addr)
			return lc.ListenPacket(context.Background(), "udp", addr)
		},
		stream: func(addr string) (net.Listener, error) {
			if fails < n {
				fails++
				return nil, errors.New("bind: forbidden")
			}
			return lc.Listen(context.Background(), "tcp", addr)
		},
	}, &asked
}

// TestBindPairLeavesReservedBlock covers #204: after a failed TCP bind the
// retries ask for explicit ports instead of another OS-picked one, and the
// pair ends up on one port.
func TestBindPairLeavesReservedBlock(t *testing.T) {
	l, asked := failingPair(t, 3)
	pick := func() int {
		// Draw from randomPort, as the server does, and keep a port that is
		// free for both UDP and TCP. An OS-assigned port would come from the
		// ephemeral range, which on Windows hosts with Hyper-V or WinNAT can
		// sit inside a reserved TCP block and fail the real bind (#254).
		for range 100 {
			port := randomPort()
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				continue
			}
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
			_ = pc.Close()
			if err != nil {
				continue
			}
			_ = ln.Close()
			return port
		}
		t.Fatal("no free UDP+TCP port in 100 tries")
		return 0
	}
	pc, ln, err := bindPair("127.0.0.1", l, pick)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close(); _ = ln.Close() }()
	// One OS-picked attempt, the three forced failures' explicit retries,
	// and, should a picked port be taken between the check and the bind,
	// more explicit ones.
	if len(*asked) < 4 {
		t.Fatalf("UDP binds %v, want at least 4 (one OS-picked, then explicit)", *asked)
	}
	if !strings.HasSuffix((*asked)[0], ":0") {
		t.Errorf("first attempt %q, want an OS-picked port", (*asked)[0])
	}
	for i, a := range (*asked)[1:] {
		if strings.HasSuffix(a, ":0") {
			t.Errorf("retry %d asked for %q; want an explicit port", i+1, a)
		}
	}
	if pc.LocalAddr().(*net.UDPAddr).Port != ln.Addr().(*net.TCPAddr).Port {
		t.Errorf("UDP %s and TCP %s are on different ports", pc.LocalAddr(), ln.Addr())
	}
}

// TestBindPairGivesUp: when no TCP bind succeeds, bindPair stops at its cap
// and says why.
func TestBindPairGivesUp(t *testing.T) {
	l, asked := failingPair(t, 1<<30)
	_, _, err := bindPair("127.0.0.1", l, func() int { return 0 })
	if !errors.Is(err, errNoPair) || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("err = %v, want errNoPair wrapping the last bind error", err)
	}
	if len(*asked) != pairAttempts {
		t.Errorf("%d attempts, want %d", len(*asked), pairAttempts)
	}
}

// TestBindPairUDPUnavailable: an error binding the OS-picked UDP port is
// returned at once, since retrying cannot help.
func TestBindPairUDPUnavailable(t *testing.T) {
	calls := 0
	l := pairListeners{
		packet: func(string) (net.PacketConn, error) { calls++; return nil, errors.New("no udp") },
		stream: func(string) (net.Listener, error) { t.Fatal("TCP bound without UDP"); return nil, nil },
	}
	if _, _, err := bindPair("127.0.0.1", l, randomPort); err == nil || errors.Is(err, errNoPair) || calls != 1 {
		t.Fatalf("err = %v after %d calls, want one listen udp error", err, calls)
	}
}
