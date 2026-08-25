// Command go_loopback executes the msn-2026-0005 decisive local experiment:
// placement of the FIPS 203 Section 7.2 encapsulation-key checks in Go's
// TLS 1.3 X25519MLKEM768 server path (draft-ietf-tls-ecdhe-mlkem Section 4.2).
//
// Evidence families:
//
//   - library-parse: executed mlkem.NewEncapsulationKey768 verdicts on
//     tampered ML-KEM-768 encapsulation keys (parse-boundary placement).
//   - tls-wire: executed crypto/tls 1.3 handshakes over net.Pipe through an
//     in-path mutator that rewrites the client's X25519MLKEM768 key_share
//     ML-KEM portion on the wire, recording whether the server aborts with
//     alert illegal_parameter (end-to-end placement).
//
// Stdlib only. Output is TSV plus META/CITE/SUMMARY lines, written to stdout,
// a console log, and a report file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	groupX25519MLKEM768 = 0x11EC
	extTypeKeyShare     = 51
	hsTypeClientHello   = 1
	ekSize              = 1184 // mlkem.EncapsulationKeySize768
	x25519Size          = 32
	shareSize           = ekSize + x25519Size // 1216
)

// ---------------------------------------------------------------------------
// logger: fan-out to stdout, console log file, and TSV report file
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
	l.printf("TSV| %s", strings.Join(fields, " | ")+"\n")
}

func (l *logger) close() {
	l.console.Close()
	l.tsv.Close()
}

// ---------------------------------------------------------------------------
// library-parse section: direct NewEncapsulationKey768 verdicts
// ---------------------------------------------------------------------------

func classifyLibErr(err error) (class, msg string) {
	if err == nil {
		return "-", "-"
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "length"):
		return "length", m
	case strings.Contains(m, "encoding"), strings.Contains(m, "unreduced"):
		return "modulus", m
	default:
		return "other", m
	}
}

// lane edits over the little-endian packed 12-bit coefficient layout:
// coeff[i] low half occupies byte pair (b0,b1) as b0 | ((b1&0x0F)<<8);
// ek layout is 384 B encoded t-hat (modulus-checked) then 32 B rho seed
// (unconstrained), so the last coefficient lane sits at bytes 762..764.
const (
	coeffQ    = 3329 // == q, exactly at the rejection boundary
	coeffQMax = 4095 // largest 12-bit value
	polyLo    = 762  // last ByteDecode12 triplet holds coeffs 254,255
	tailHi    = 764  // coeff255 = (b[763]>>4) | b[764]<<4
	seedStart = 1152 // ek[1152:1184] is the rho seed, no modulus constraint
)

func libRows(lg *logger) {
	k, err := mlkem.GenerateKey768()
	if err != nil {
		lg.printf("FATAL|GenerateKey768: %v\n", err)
		os.Exit(1)
	}
	base := append([]byte(nil), k.EncapsulationKey().Bytes()...)

	editors := map[string]func(b []byte){
		"canonical":      func(b []byte) {},
		"coeff0_eq_q":    func(b []byte) { b[0] = 0x01; b[1] = b[1]&0xF0 | 0x0D }, // coeff0 := 3329 == q
		"coeff0_eq_4095": func(b []byte) { b[0] = 0xFF; b[1] |= 0x0F },
		"coeff255_4095":  func(b []byte) { b[polyLo+1] |= 0xF0; b[tailHi] = 0xFF },
		"seed_byte_set":  func(b []byte) { b[seedStart+31] = 0xFF }, // rho region: no modulus constraint
	}
	for _, name := range []string{"canonical", "coeff0_eq_q", "coeff0_eq_4095", "coeff255_4095", "seed_byte_set"} {
		b := append([]byte(nil), base...)
		editors[name](b)
		_, err := mlkem.NewEncapsulationKey768(b)
		class, msg := classifyLibErr(err)
		verdict := "accepted"
		if err != nil {
			verdict = "rejected"
		}
		lg.tsvln("library-parse", name, fmt.Sprint(len(b)), verdict, class, msg)
	}

	// Length-class variants.
	trunc := base[:len(base)-1]
	_, err = mlkem.NewEncapsulationKey768(trunc)
	class, msg := classifyLibErr(err)
	verdict := "accepted"
	if err != nil {
		verdict = "rejected"
	}
	lg.tsvln("library-parse", "truncate_last_byte", fmt.Sprint(len(trunc)), verdict, class, msg)

	appended := append(append([]byte(nil), base...), 0xAA)
	_, err = mlkem.NewEncapsulationKey768(appended)
	class, msg = classifyLibErr(err)
	verdict = "accepted"
	if err != nil {
		verdict = "rejected"
	}
	lg.tsvln("library-parse", "append_extra_byte", fmt.Sprint(len(appended)), verdict, class, msg)

	// Single-bit flip of ek[0]: outcome depends on the random base key
	// (bit 7 of coeff0), so aggregate over N trials instead of one shot.
	const trials = 64
	var accepted, rejected int
	for i := 0; i < trials; i++ {
		kk, err := mlkem.GenerateKey768()
		if err != nil {
			continue
		}
		b := kk.EncapsulationKey().Bytes()
		b[0] ^= 0x80
		if _, err := mlkem.NewEncapsulationKey768(b); err != nil {
			rejected++
		} else {
			accepted++
		}
	}
	// Forced-crossing companion: same single-bit flip applied to a key whose
	// coeff0 is first pinned to 3328 (=q-1, bit 7 clear); the flip pushes
	// coeff0 to 3456 >= q, so this one MUST be rejected.
	pre := append([]byte(nil), base...)
	pre[0] = 0x00
	pre[1] = pre[1]&0xF0 | 0x0D // coeff0 := 3328
	if _, err := mlkem.NewEncapsulationKey768(pre); err != nil {
		lg.tsvln("library-parse", "bitflip_b0_pre3328_base", "1184", "setup-unexpected", "modulus", err.Error())
	} else {
		pre[0] ^= 0x80 // coeff0 := 3456
		_, err := mlkem.NewEncapsulationKey768(pre)
		class, msg := classifyLibErr(err)
		verdict := "accepted"
		if err != nil {
			verdict = "rejected"
		}
		lg.tsvln("library-parse", "bitflip_b0_xor80_pre3328", "1184", verdict, class, msg)
	}

	lg.tsvln("library-parse", fmt.Sprintf("bitflip_b0_xor80_n%d", trials),
		"1184", fmt.Sprintf("mixed_accepted=%d_rejected=%d", accepted, rejected),
		"base-key-dependent", "single-bit flip crosses q only when original coeff0 high bits allow")
}

// ---------------------------------------------------------------------------
// tls-wire section: net.Pipe loopback with in-path ClientHello mutator
// ---------------------------------------------------------------------------

type chLayout struct {
	body      []byte
	entryPos  int // absolute offset of the X25519MLKEM768 key_share entry (group field)
	entryLen  int // exchange length of that entry (expect 1216)
	vecLenPos int // offset of the key_share client_shares vector length
	extLenPos int // offset of the key_share extension length
	extTotPos int // offset of the extensions total length
	hsLenPos  int // offset of the handshake message length (3 bytes)
}

// parseClientHello walks the minimal structure needed to locate the
// X25519MLKEM768 key_share entry. Returns ok=false (and passes through
// unmutated) for anything unexpected, including fragmentation across records.
func parseClientHello(body []byte) (*chLayout, bool) {
	if len(body) < 8 || body[0] != hsTypeClientHello {
		return nil, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	end := 4 + hsLen
	if end > len(body) {
		return nil, false // spans multiple records; refuse rather than guess
	}
	p := 4
	p += 2  // legacy_version
	p += 32 // random
	if p >= end {
		return nil, false
	}
	sid := int(body[p])
	p += 1 + sid
	if p+2 > end {
		return nil, false
	}
	cs := int(binary.BigEndian.Uint16(body[p:])) // vector length counts bytes
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
func decU24(b []byte, off int) int { return int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2]) }
func encU16(b []byte, off, v int)  { binary.BigEndian.PutUint16(b[off:], uint16(v)) }
func encU24(b []byte, off, v int) {
	b[off] = byte(v >> 16)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v)
}

// applyEdit rewrites the located ek in place according to mode. Returns a
// description of what happened.
func applyEdit(ch *chLayout, mode string) (applied bool, detail string) {
	d := ch.entryPos + 4 // ek starts here (ML-KEM portion comes first for 0x11EC)
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
	case "wire_bitflip_b0_xor80":
		ch.body[d] ^= 0x80
		return true, "ek[0] ^= 0x80 (outcome base-key-dependent)"
	case "truncate_last_byte":
		cut := d + shareSize - 1 // last ek byte
		if ch.entryLen != shareSize || cut >= len(ch.body) {
			return false, fmt.Sprintf("unexpected entry length %d", ch.entryLen)
		}
		copy(ch.body[cut:], ch.body[cut+1:]) // shift tail left by 1
		ch.body = ch.body[:len(ch.body)-1]
		encU16(ch.body, ch.entryPos+2, decU16(ch.body, ch.entryPos+2)-1) // entry exchange length
		encU16(ch.body, ch.vecLenPos, decU16(ch.body, ch.vecLenPos)-1)   // shares vector length
		encU16(ch.body, ch.extLenPos, decU16(ch.body, ch.extLenPos)-1)   // key_share ext length
		encU16(ch.body, ch.extTotPos, decU16(ch.body, ch.extTotPos)-1)   // extensions total length
		encU24(ch.body, ch.hsLenPos, decU24(ch.body, ch.hsLenPos)-1)     // handshake length
		return true, "ek shrunk to 1183 B, all six length fields repaired (-1)"
	default:
		return false, "unknown mode"
	}
}

// debugDump explains a failed ClientHello walk when GO_LOOPBACK_DEBUG=1.
func (m *mitm) debugDump(body []byte) {
	if os.Getenv("GO_LOOPBACK_DEBUG") != "1" {
		return
	}
	hsLen := decU24(body, 1)
	fmt.Fprintf(os.Stderr, "DEBUG|bodyLen=%d hsType=%d hsLen=%d end=%d fragmented=%v\n",
		len(body), body[0], hsLen, 4+hsLen, 4+hsLen > len(body))
	n := len(body)
	if n > 96 {
		n = 96
	}
	fmt.Fprintf(os.Stderr, "DEBUG|head96=% x\n", body[:n])
	if 4+hsLen <= len(body) {
		end := 4 + hsLen
		p := 4 + 2 + 32
		sid := int(body[p])
		p += 1 + sid
		var cs, comp int
		if p+2 <= end {
			cs = decU16(body, p)
			p += 2 + cs // vector length counts bytes
		}
		if p < end {
			comp = int(body[p])
			p += 1 + comp
		}
		var extTot int
		if p+2 <= end {
			extTot = decU16(body, p)
		}
		fmt.Fprintf(os.Stderr, "DEBUG|afterCS p=%d sid=%d cs=%d comp=%d extTot=%d extEnd=%d\n",
			p, sid, cs, comp, extTot, p+2+extTot)
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

// pump relays server->client verbatim and intercepts only the client's first
// record (the ClientHello flight), applying the configured edit once.
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
	if head[0] == 22 /* handshake */ {
		if ch, ok := parseClientHello(body); ok {
			m.found = true
			applied, detail := applyEdit(ch, m.mode)
			m.applied = applied
			m.detail = detail
			body = ch.body
		} else {
			m.fragmented = m.mode != "control"
			m.detail = "client hello not parsed in first record; passed through unmutated"
			m.debugDump(body)
		}
	}
	buf := append(append([]byte(nil), head...), body...)
	encU16(buf, 3, len(body)) // record length tracks body edits (truncate shrinks it)
	if _, err := m.srv.Write(buf); err != nil {
		m.cli.Close()
		return
	}
	io.Copy(m.srv, m.cli) // remaining client -> server traffic
	m.srv.Close()
}

type wireResult struct {
	serverErr string
	clientErr string
}

func runHandshake(mode string, cert tls.Certificate) (wireResult, *mitm) {
	cRaw, cMut := net.Pipe() // client <-> mutator
	sMut, sRaw := net.Pipe() // mutator <-> server
	for _, c := range []net.Conn{cRaw, cMut, sMut, sRaw} {
		c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	m := &mitm{cli: cMut, srv: sMut, mode: mode}
	go m.pump()

	serverCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, // force the hybrid group
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
	}

	type hsOut struct {
		side string
		err  error
	}
	done := make(chan hsOut, 2)
	go func() {
		sc := tls.Server(sRaw, serverCfg)
		done <- hsOut{"server", sc.Handshake()}
	}()
	go func() {
		cc := tls.Client(cRaw, clientCfg)
		done <- hsOut{"client", cc.Handshake()}
	}()

	res := wireResult{}
	deadline := time.After(35 * time.Second)
	got := 0
collect:
	for got < 2 {
		select {
		case o := <-done:
			got++
			if o.side == "server" {
				res.serverErr = errStr(o.err)
			} else {
				res.clientErr = errStr(o.err)
			}
		case <-deadline:
			break collect
		}
	}
	for _, c := range []net.Conn{cRaw, cMut, sMut, sRaw} {
		c.Close()
	}
	return res, m
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func normAlert(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", " ")
}

func alertFromClientErr(s string) string {
	switch {
	case s == "":
		return "none(handshake-succeeded)"
	case strings.Contains(normAlert(s), "illegal parameter"):
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

func wireRows(lg *logger, cert tls.Certificate, modes []string) {
	expectations := map[string]string{
		"control":               "success",
		"wire_coeff0_eq_q":      "abort:illegal_parameter",
		"wire_coeff0_eq_4095":   "abort:illegal_parameter",
		"wire_coeff255_eq_4095": "abort:illegal_parameter",
		"truncate_last_byte":    "abort:illegal_parameter",
		"wire_bitflip_b0_xor80": "indeterminate(base-key-dependent)",
	}
	for _, mode := range modes {
		res, m := runHandshake(mode, cert)
		wireMutated := m.applied
		handshake := "success"
		if res.serverErr != "" || res.clientErr != "" {
			handshake = fmt.Sprintf("failure(server_err='%s' client_err='%s')", res.serverErr, res.clientErr)
		}
		alert := alertFromClientErr(res.clientErr)
		parseCol := "cited:not-directly-observed(NewEncapsulationKey768->parseEK->polyByteDecode,a>=q@field.go:18)"
		verdict := expectations[mode]
		met := "?"
		switch {
		case verdict == "success":
			if handshake == "success" {
				met = "MET"
			} else {
				met = "UNMET"
			}
		case strings.HasPrefix(verdict, "abort:"):
			want := strings.TrimPrefix(verdict, "abort:")
			if handshake != "success" && strings.Contains(alert, want) {
				met = "MET"
			} else {
				met = "UNMET"
			}
		}
		lg.tsvln("tls-wire", mode,
			fmt.Sprint(wireMutated)+fmt.Sprint(";found=", m.found, ";fragmented=", m.fragmented),
			handshake, alert, parseCol+";verdict="+verdict+";expectation="+met)
	}
}

// ---------------------------------------------------------------------------
// certificate
// ---------------------------------------------------------------------------

func testCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-loopback-test"},
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
	reportPath := "reports/go_loopback_report.tsv"
	consolePath := "reports/go_loopback_console.log"
	if len(os.Args) > 1 {
		reportPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		consolePath = os.Args[2]
	}
	lg, err := newLogger(consolePath, reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		os.Exit(1)
	}
	defer lg.close()

	lg.printf("META|experiment=msn-2026-0005 decisive local loopback|tool=%s %s/%s|time=%s\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, time.Now().UTC().Format(time.RFC3339))
	lg.printf("META|deps=stdlib-only|groups_forced=X25519MLKEM768(0x11EC)|transport=net.Pipe x2 + MITM mutator\n")
	lg.printf("META|determinism=crypto/rand for keys/nonces/cert; lane-overwrite verdicts input-determined; bitflip variants aggregated over N trials\n")
	lg.printf("CITE|crypto/internal/fips140/mlkem/mlkem768.go:374 NewEncapsulationKey768 -> :384 parseEK (len check :385) -> polyByteDecode field.go:164 -> fieldCheckReduced field.go:17-22, a>=q reject at :18\n")
	lg.printf("CITE|crypto/tls/handshake_server_tls13.go:254 ke.serverSharedSecret(clientKeyShare) -> :256 sendAlert(alertIllegalParameter) on any error\n")
	lg.printf("CITE|crypto/tls/key_schedule.go:83-85,98-101 newMLKEMPublicKey768==mlkem.NewEncapsulationKey768; :200-224 hybrid serverSharedSecret splits ek-first for 0x11EC (:206-208)\n")

	lg.printf("\n# family|variant|input_len|verdict|error_class|error_string\n")
	libRows(lg)

	lg.printf("\n# family|variant|wire_mutated|handshake_result|alert_observed|mlkem_parse_result\n")
	cert := testCert()
	modes := []string{
		"control",
		"wire_coeff0_eq_q",
		"wire_coeff0_eq_4095",
		"wire_coeff255_eq_4095",
		"truncate_last_byte",
		"wire_bitflip_b0_xor80",
	}
	wireRows(lg, cert, modes)

	lg.printf("\nDONE|%s\n", time.Now().UTC().Format(time.RFC3339))
}
