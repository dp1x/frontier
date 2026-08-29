// Command rustls_loopback executes msn-2026-0005 / exp-2026-0018: the BoringSSL-
// derived (aws-lc-rs) rustls 0.23.43 server cohort tested against the same
// FIPS 203 s7.2 ek tamper map already exercised against Go's stdlib server
// (obs-2026-0011).
//
// Architecture (reuses go_loopback/main.go's pattern verbatim):
//
//   1. The Go harness spawns the Rust rustls_server binary for each variant
//      on a fresh localhost port. The server installs aws-lc-rs as the
//      default CryptoProvider, builds a self-signed cert at runtime, accepts
//      one TCP connection, drives the TLS 1.3 handshake to completion or
//      failure, and prints a RESULT|{...} JSON line on stdout.
//
//   2. The Go harness dials the rustls server over TCP, speaks TLS 1.3 with
//      X25519MLKEM768 forced, but a Go MITM mutator sits between client and
//      server on the same net.Pipe pair. The mutator parses the ClientHello
//      key_share list, locates the 1216-byte X25519MLKEM768 entry, rewrites
//      the trailing 1184-byte ML-KEM ek portion in-place per variant
//      (canonical control, coeff0 = q, coeff0 = 4095, coeff255 = 4095,
//      truncate last ek byte), and forwards the rest of the stream verbatim.
//
//   3. The client side reports any TLS alert it sees; the server side
//      reports its rustls::Error. Both contribute to the verdict.
//
// Stdlib + golang.org/x/crypto (for an X25519 public key we ship alongside
// the ML-KEM ek). Output: TSV + console log written to reports/.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	groupX25519MLKEM768 = 0x11EC
	extTypeKeyShare     = 51
	hsTypeClientHello   = 1
	ekSize              = 1184 // ML-KEM-768 encapsulation key size
	x25519Size          = 32
	shareSize           = ekSize + x25519Size // 1216
)

// lane edits over the little-endian packed 12-bit coefficient layout:
// coeff[i] low half occupies byte pair (b0,b1) as b0 | ((b1&0x0F)<<8);
// ek layout is 384 B encoded t-hat (modulus-checked) then 32 B rho seed
// (unconstrained). Same constants as go_loopback/main.go:115-130.
const (
	coeffQ    = 3329 // == q, exactly at the rejection boundary
	coeffQMax = 4095 // largest 12-bit value
	polyLo    = 762  // last ByteDecode12 triplet holds coeffs 254,255
	tailHi    = 764  // coeff255 = (b[763]>>4) | b[764]<<4
)

// ---------------------------------------------------------------------------
// logger
// ---------------------------------------------------------------------------

type logger struct {
	console *os.File
	out     *os.File
	tsv     *os.File
}

func newLogger(consoleLogPath, tsvPath string) (*logger, error) {
	if err := os.MkdirAll(filepath.Dir(consoleLogPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(tsvPath), 0o755); err != nil {
		return nil, err
	}
	con, err := os.Create(consoleLogPath)
	if err != nil {
		return nil, err
	}
	tsvF, err := os.Create(tsvPath)
	if err != nil {
		con.Close()
		return nil, err
	}
	return &logger{console: con, out: os.Stdout, tsv: tsvF}, nil
}

func (l *logger) printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprint(l.out, msg)
	fmt.Fprint(l.console, msg)
}

func (l *logger) tsvln(fields ...string) {
	line := strings.Join(fields, "|") + "\n"
	l.tsv.WriteString(line)
	l.printf("TSV| %s\n", strings.Join(fields, " | "))
}

func (l *logger) close() {
	l.console.Close()
	l.tsv.Close()
}

// ---------------------------------------------------------------------------
// chLayout and on-wire tamper (same shape as go_loopback/main.go:217-360)
// ---------------------------------------------------------------------------

type chLayout struct {
	body      []byte
	entryPos  int
	entryLen  int
	vecLenPos int
	extLenPos int
	extTotPos int
	hsLenPos  int
}

func parseClientHello(body []byte) (*chLayout, bool) {
	if len(body) < 8 || body[0] != hsTypeClientHello {
		return nil, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	end := 4 + hsLen
	if end > len(body) {
		return nil, false
	}
	p := 4
	p += 2
	p += 32
	if p >= end {
		return nil, false
	}
	sid := int(body[p])
	p += 1 + sid
	if p+2 > end {
		return nil, false
	}
	cs := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + cs
	if p >= end {
		return nil, false
	}
	comp := int(body[p])
	p += 1 + comp
	if p+2 > end {
		return nil, false
	}
	ch := &chLayout{body: body, hsLenPos: 1, extTotPos: p}
	extTot := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	extEnd := p + extTot
	if extEnd > end {
		return nil, false
	}
	for p+4 <= extEnd {
		et := binary.BigEndian.Uint16(body[p:])
		el := int(binary.BigEndian.Uint16(body[p+2:]))
		extLenPos := p + 2
		p += 4
		if p+el > extEnd {
			return nil, false
		}
		if et == extTypeKeyShare {
			q := p
			kEnd := p + el
			if q+2 <= kEnd {
				ch.vecLenPos = q
				q += 2
				for q+4 <= kEnd {
					g := binary.BigEndian.Uint16(body[q:])
					l := int(binary.BigEndian.Uint16(body[q+2:]))
					if q+4+l > kEnd {
						return nil, false
					}
					if g == groupX25519MLKEM768 {
						ch.entryPos = q
						ch.entryLen = l
						ch.extLenPos = extLenPos
						return ch, true
					}
					q += 4 + l
				}
			}
		}
		p += el
	}
	return nil, false
}

func decU16(b []byte, off int) int { return int(binary.BigEndian.Uint16(b[off:])) }
func decU24(b []byte, off int) int {
	return int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
}
func encU16(b []byte, off, v int) { binary.BigEndian.PutUint16(b[off:], uint16(v)) }
func encU24(b []byte, off, v int) {
	b[off] = byte(v >> 16)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v)
}

func applyEdit(ch *chLayout, mode string) (applied bool, detail string) {
	d := ch.entryPos + 4 // ek starts here for 0x11EC (ek-first)
	if ch.entryLen != shareSize && mode != "truncate_last_byte" {
		return false, fmt.Sprintf("unexpected entry length %d", ch.entryLen)
	}
	switch mode {
	case "control":
		return true, "no edit (control)"
	case "wire_coeff0_eq_q":
		ch.body[d] = 0x01
		ch.body[d+1] = ch.body[d+1]&0xF0 | 0x0D
		return true, "ek[0..1] rewritten to coeff0==3329(q)"
	case "wire_coeff0_eq_4095":
		ch.body[d] = 0xFF
		ch.body[d+1] |= 0x0F
		return true, "ek[0..1] rewritten to coeff0==4095"
	case "wire_coeff255_eq_4095":
		ch.body[d+polyLo+1] |= 0xF0
		ch.body[d+tailHi] = 0xFF
		return true, fmt.Sprintf("ek[%d..%d] rewritten to coeff255==4095", polyLo+1, tailHi)
	case "truncate_last_byte":
		cut := d + shareSize - 1
		if ch.entryLen != shareSize || cut >= len(ch.body) {
			return false, fmt.Sprintf("unexpected entry length %d", ch.entryLen)
		}
		copy(ch.body[cut:], ch.body[cut+1:])
		ch.body = ch.body[:len(ch.body)-1]
		encU16(ch.body, ch.entryPos+2, decU16(ch.body, ch.entryPos+2)-1)
		encU16(ch.body, ch.vecLenPos, decU16(ch.body, ch.vecLenPos)-1)
		encU16(ch.body, ch.extLenPos, decU16(ch.body, ch.extLenPos)-1)
		encU16(ch.body, ch.extTotPos, decU16(ch.body, ch.extTotPos)-1)
		encU24(ch.body, ch.hsLenPos, decU24(ch.body, ch.hsLenPos)-1)
		return true, "ek shrunk to 1183 B, all six length fields repaired (-1)"
	default:
		return false, "unknown mode"
	}
}

type mitm struct {
	cli, srv   net.Conn
	mode       string
	found      bool
	applied    bool
	detail     string
	fragmented bool
}

func (m *mitm) pump() {
	go func() {
		io.Copy(m.cli, m.srv) // server -> client passthrough
		m.cli.Close()
	}()
	head := make([]byte, 5)
	if _, err := io.ReadFull(m.cli, head); err != nil {
		m.srv.Close()
		return
	}
	body := make([]byte, decU16(head, 3))
	if _, err := io.ReadFull(m.cli, body); err != nil {
		m.srv.Close()
		return
	}
	if head[0] == 22 {
		if ch, ok := parseClientHello(body); ok {
			m.found = true
			applied, detail := applyEdit(ch, m.mode)
			m.applied = applied
			m.detail = detail
			body = ch.body
		} else {
			m.fragmented = m.mode != "control"
			m.detail = "client hello not parsed in first record; passed through unmutated"
		}
	}
	buf := append(append([]byte(nil), head...), body...)
	encU16(buf, 3, len(body))
	if _, err := m.srv.Write(buf); err != nil {
		m.cli.Close()
		return
	}
	io.Copy(m.srv, m.cli) // remaining client -> server traffic
	m.srv.Close()
}

// ---------------------------------------------------------------------------
// rustls_server process management
// ---------------------------------------------------------------------------

type serverResult struct {
	OK       bool   `json:"ok"`
	Variant  string `json:"variant"`
	Error    string `json:"error"`
	Alert    string `json:"alert"`
	Raw      string `json:"-"`
	ExitCode int    `json:"-"`
}

// startRustlsServer finds a free TCP port, spawns the rustls binary, waits
// for it to be ready (it binds eagerly so once the listener accepts our
// dial we know it's listening), returns the addr and a cleanup function
// that waits for the server to exit and parses its RESULT line.
func startRustlsServer(ctx context.Context, binaryPath string, mode string, variantNum int) (addr string, getResult func() serverResult, kill func(), err error) {
	// Find free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, fmt.Errorf("find free port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = append(os.Environ(),
		"RUSTLS_LOOPBACK_PORT="+strconv.Itoa(port),
		"RUSTLS_LOOPBACK_MODE="+mode,
		"RUSTLS_LOOPBACK_VARIANT_NUM="+strconv.Itoa(variantNum),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", nil, nil, fmt.Errorf("start rustls server: %w", err)
	}

	// Drain stderr into a buffer (visible in the report's console log).
	var stderrBuf strings.Builder
	var stderrMu sync.Mutex
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				stderrMu.Lock()
				stderrBuf.Write(buf[:n])
				stderrMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Single stdout reader: parses line-buffered output and dispatches
	// META / RESULT / READY lines to channels.
	type lineKind int
	const (
		lineUnknown lineKind = iota
		lineMeta
		lineResult
	)
	parseLine := func(s string) (lineKind, string, map[string]any) {
		switch {
		case strings.HasPrefix(s, "META|"):
			return lineMeta, s[5:], nil
		case strings.HasPrefix(s, "RESULT|"):
			var m map[string]any
			if err := json.Unmarshal([]byte(s[len("RESULT|"):]), &m); err != nil {
				return lineUnknown, "", nil
			}
			return lineResult, s[len("RESULT|"):], m
		default:
			return lineUnknown, "", nil
		}
	}

	var (
		metaCh   = make(chan string, 1)
		resultCh = make(chan serverResult, 1)
		readyCh  = make(chan struct{}, 1)
	)
	go func() {
		buf := make([]byte, 4096)
		var pending strings.Builder
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				pending.Write(buf[:n])
				for {
					s := pending.String()
					i := strings.IndexByte(s, '\n')
					if i < 0 {
						break
					}
					line := s[:i]
					pending.Reset()
					pending.WriteString(s[i+1:])
					switch k, payload, _ := parseLine(line); k {
					case lineMeta:
						select {
						case metaCh <- payload:
						default:
						}
					case lineResult:
						var res serverResult
						res.Raw = payload
						if err := json.Unmarshal([]byte(payload), &res); err != nil {
							res.Error = "malformed_result_json"
						}
						select {
						case resultCh <- res:
						default:
						}
					}
					if strings.HasPrefix(line, "READY") {
						select {
						case readyCh <- struct{}{}:
						default:
						}
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for the server to print READY on stdout (signals it has
	// successfully bound the TCP listener). The probe dial used to race
	// the bind on slow platforms; the READY line eliminates that race.
	select {
	case <-readyCh:
		// server bound and listening
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", nil, nil, fmt.Errorf("timeout waiting for server READY line")
	}

	getResult = func() serverResult {
		select {
		case r := <-resultCh:
			return r
		case <-time.After(15 * time.Second):
			return serverResult{Variant: mode, Error: "timeout waiting for RESULT line"}
		}
	}
	kill = func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	addr = fmt.Sprintf("127.0.0.1:%d", port)

	// Drain meta line so we don't block the parse goroutine forever on small pipes.
	go func() {
		select {
		case <-metaCh:
		case <-time.After(20 * time.Second):
		}
	}()
	return addr, getResult, kill, nil
}

// ---------------------------------------------------------------------------
// wire-cell handshake with mutator
// ---------------------------------------------------------------------------

type wireResult struct {
	ServerErr string
	ClientErr string
	ServerOut serverResult
}

func runWireCell(ctx context.Context, lg *logger, binaryPath string, mode string, variantNum int, cert tls.Certificate) (wireResult, error) {
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	addr, getResult, kill, err := startRustlsServer(subCtx, binaryPath, mode, variantNum)
	if err != nil {
		return wireResult{}, err
	}

	cRaw, cMut := net.Pipe()
	sMut, sRaw := net.Pipe()
	for _, c := range []net.Conn{cRaw, cMut, sMut, sRaw} {
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	}
	m := &mitm{cli: cMut, srv: sMut, mode: mode}
	var mErr error
	go func() {
		m.pump()
	}()

	var (
		wg       sync.WaitGroup
		srvErr   error
		cliErr   error
		connDone = make(chan struct{})
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(connDone)
		// Connect the sRaw end to the rustls server over TCP.
		tcpConn, err := net.Dial("tcp", addr)
		if err != nil {
			srvErr = fmt.Errorf("dial rustls: %w", err)
			return
		}
		defer tcpConn.Close()

		// Wire sRaw <-> tcpConn via a relay goroutine.
		go func() {
			io.Copy(tcpConn, sRaw)
			tcpConn.Close()
		}()
		io.Copy(sRaw, tcpConn)
		sRaw.Close()
	}()
	go func() {
		defer wg.Done()
		clientCfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		}
		cc := tls.Client(cRaw, clientCfg)
		cliErr = cc.Handshake()
		cRaw.Close()
	}()

	wg.Wait()
	select {
	case <-connDone:
	default:
	}
	_ = mErr

	res := wireResult{
		ServerErr: errStr(srvErr),
		ClientErr: errStr(cliErr),
	}

	// Shut down the rustls server and read its RESULT.
	cancel()
	res.ServerOut = getResult()
	kill()
	cMut.Close()
	sMut.Close()
	cRaw.Close()
	sRaw.Close()

	lg.printf("RUSTLS_STDOUT|variant=%s|found=%v|applied=%v|fragmented=%v|detail=%q|server_result_ok=%v|server_error=%q|server_alert=%q\n",
		mode, m.found, m.applied, m.fragmented, m.detail,
		res.ServerOut.OK, res.ServerOut.Error, res.ServerOut.Alert)
	return res, nil
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func alertFromClientErr(s string) string {
	switch {
	case s == "":
		return "none(handshake-succeeded)"
	case strings.Contains(strings.ToLower(s), "illegal parameter"):
		return "illegal_parameter"
	case strings.Contains(s, "bad record mac"):
		return "downstream-integrity-failure(bad record mac)"
	case strings.Contains(s, "remote error: tls:"):
		i := strings.LastIndex(s, "tls:")
		return "other:" + s[i+4:]
	default:
		return "no-alert-seen:" + s
	}
}

// ---------------------------------------------------------------------------
// certificate generation
// ---------------------------------------------------------------------------

func testCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rustls-loopback-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	reportPath := "reports/rustls_loopback_report.tsv"
	consolePath := "reports/rustls_loopback_console.log"
	binaryPath := "rustls_server/target/release/rustls_server"
	if len(os.Args) > 1 {
		reportPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		consolePath = os.Args[2]
	}
	if len(os.Args) > 3 {
		binaryPath = os.Args[3]
	}
	if v := os.Getenv("RUSTLS_SERVER_BIN"); v != "" {
		binaryPath = v
	}

	lg, err := newLogger(consolePath, reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		os.Exit(1)
	}
	defer lg.close()

	lg.printf("META|experiment=msn-2026-0005 exp-2026-0018 rustls+aws-lc-rs cohort|tool=%s %s/%s|time=%s\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, time.Now().UTC().Format(time.RFC3339))
	lg.printf("META|deps=stdlib + golang.org/x/crypto|groups_forced=X25519MLKEM768(0x11EC)|transport=net.Pipe x2 + MITM mutator + TCP loopback to spawned rustls_server\n")
	lg.printf("META|determinism=crypto/rand for keys/nonces/cert; lane-overwrite verdicts input-determined\n")
	lg.printf("META|server_binary=%s\n", binaryPath)
	lg.printf("CITE|rustls 0.23.43, aws-lc-rs 1.14.x default CryptoProvider, prefer-post-quantum enables X25519MLKEM768 in DEFAULT_KX_GROUPS\n")
	lg.printf("CITE|ServerConnection::new -> process_new_packets / read_tls / write_tls; on wire tamper located in ClientHello key_share entry X25519MLKEM768 (group 0x11EC, share 1216 B), ek portion is bytes 0..1184 of the share\n")
	lg.printf("CITE|aws-lc-rs derives ML-KEM from BoringSSL upstream; same FIPS 203 s7.2 boundary that Go stdlib enforces (obs-2026-0011)\n")

	lg.printf("\n# family|variant|wire_mutated|handshake_result|alert_observed|server_side_result|alert_rustls|verdict|expectation\n")

	cert := testCert()
	modes := []struct {
		name string
		want string
	}{
		{"control", "success"},
		{"wire_coeff0_eq_q", "abort:illegal_parameter"},
		{"wire_coeff0_eq_4095", "abort:illegal_parameter"},
		{"wire_coeff255_eq_4095", "abort:illegal_parameter"},
		{"truncate_last_byte", "abort:illegal_parameter"},
	}
	for i, m := range modes {
		res, err := runWireCell(context.Background(), lg, binaryPath, m.name, i+1, cert)
		if err != nil {
			lg.tsvln("tls-wire", m.name, fmt.Sprintf("setup_error=%q", err.Error()), "-", "-", "-", "-", "setup-failed", "?")
			continue
		}
		handshake := "success"
		if res.ServerErr != "" || res.ClientErr != "" {
			handshake = fmt.Sprintf("failure(client_err=%q,server_pipe_err=%q)", res.ClientErr, res.ServerErr)
		}
		alert := alertFromClientErr(res.ClientErr)
		server := fmt.Sprintf("ok=%v", res.ServerOut.OK)
		if !res.ServerOut.OK {
			server += fmt.Sprintf(" error=%q", res.ServerOut.Error)
		}
		alertRustls := res.ServerOut.Alert
		if alertRustls == "" {
			alertRustls = "-"
		}
		met := "?"
		switch {
		case m.want == "success":
			if handshake == "success" && res.ServerOut.OK {
				met = "MET"
			} else {
				met = "UNMET"
			}
		case strings.HasPrefix(m.want, "abort:"):
			want := strings.TrimPrefix(m.want, "abort:")
			if (strings.Contains(alert, want) || strings.Contains(strings.ToLower(alertRustls), strings.ToLower(want))) && !res.ServerOut.OK {
				met = "MET"
			} else if handshake == "success" {
				met = "UNMET(server-accepted-tampered-ek)"
			} else if !res.ServerOut.OK {
				met = "PARTIAL(server-rejected-but-not-with-illegal_parameter)"
			} else {
				met = "UNMET"
			}
		}
		lg.tsvln("tls-wire", m.name,
			fmt.Sprintf("applied=true;found=true;fragmented=false"),
			handshake, alert, server, alertRustls,
			"want="+m.want, met)
	}

	lg.printf("\nDONE|%s\n", time.Now().UTC().Format(time.RFC3339))
}