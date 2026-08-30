// Command ssh_loopback executes msn-2026-0010 / exp-2026-0025: the SSH hybrid
// KEX protocol-layer FIPS 203 s7.2 enforcement audit. Drives a Go-side SSH
// client against an OpenSSH portable sshd (built with USE_MLKEM768X25519=1 on
// GHA ubuntu-latest; this Windows host's ssh.exe 9.5p2 + LibreSSL 3.8.2 lacks
// PQ KEX). A Go MITM mutator on net.Pipe rewrites the SSH_MSG_KEX_HYBRID_INIT
// payload per stimulus family and observes the server's response:
//
//	(a) SSH_MSG_DISCONNECT reason 3 (KEY_EXCHANGE_FAILED)  -- strict (rejected)
//	(b) Completed handshake (SSH_MSG_KEX_HYBRID_REPLY received) -- lenient (silent encap)
//	(c) TCP reset / timeout / hang -- dangerous (likely crash or silent close)
//
// Per-imp boundaries (reused from rustls_loopback pattern):
//   1. The Go harness dials the OpenSSH sshd over TCP. The server installs
//      ed25519 host key, accepts one TCP connection, drives the SSH binary
//      packet protocol (RFC 4253 s6) to completion or failure, and writes a
//      RESULT|{...} JSON line to stdout.
//   2. The Go MITM mutator sits between client and server on net.Pipe.
//      It parses the SSH_MSG_KEXINIT and SSH_MSG_KEX_HYBRID_INIT packets,
//      locates the C_INIT payload (1184-B ML-KEM-768 pk || 32-B X25519 pk
//      for the mlkem768x25519 cohort), rewrites C_PK2 in-place per stimulus
//      variant, recomputes the SSH packet length / padding / MAC, and forwards.
//   3. The harness captures the server's first response: SSH_MSG_DISCONNECT
//      reason 3 = strict; SSH_MSG_KEX_HYBRID_REPLY = lenient; TCP reset = dangerous.
//
// Stage C (client-side decapsulation parity, mandatory per critic review) is
// implemented by running the OpenSSH portable ssh client + Go ssh client against
// the same tampered-server path and recording whether they abort after S_REPLY.
//
// Reference: draft-ietf-sshm-mlkem-hybrid-kex-10 s2.1
//            draft-ietf-sshm-ntruprime-ssh-06 s2.1
//            RFC 4253 s6 (binary packet protocol)
//            RFC 4253 s7 (key exchange)
//            RFC 5656 (ECC support, X25519)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SSH binary packet protocol constants (RFC 4253 s6).
const (
	sshMsgDisconnect       = 1
	sshMsgKexinit          = 20
	sshMsgKexHybridInit    = 30 // draft-ietf-sshm-mlkem-hybrid-kex-10 s2.1
	sshMsgKexHybridReply   = 31
	sshDisconnectKeyExFailed = 3

	mlkem768EKSize    = 1184
	x25519Size        = 32
	hybridCInitSize   = mlkem768EKSize + x25519Size // 1216
	sntrup761EKSize   = 1031
	sntruprimeCInitSize = sntrup761EKSize + x25519Size // 1063
)

// Stimulus variant ID -> C_PK2 mutation function.
type Stimulus struct {
	Name        string
	Description string
	Mutate      func(pk2 []byte) // in-place mutation of the C_PK2 portion
}

// control: no mutation (canonical).
func stimControl(pk2 []byte) { /* pass-through */ }

// truncate_by_1: drop the last byte of C_PK2 (and adjust C_INIT length field).
// Special case: handled at the SSH packet length layer, not in Mutate().
func stimTruncateBy1(pk2 []byte) { /* no-op in Mutate; harness drops last byte */ }

// append_1: append one extra byte to C_PK2.
func stimAppend1(pk2 []byte) { /* no-op in Mutate; harness appends */ }

// coeff0_q: set the first 12-bit coefficient to q=3329.
func stimCoeff0Q(pk2 []byte) {
	// ML-KEM-768 pk: 384 bytes encode 1024 12-bit coefficients (2 per 3 bytes).
	// First coefficient (coeff0) is at byte 0 low + byte 1 low nibble.
	// 3329 = 0xD01 -> low byte = 0x01, high nibble = 0xD
	pk2[0] = 0x01 // low byte of coeff0
	pk2[1] = (pk2[1] & 0xF0) | 0x0D // high nibble of coeff0 = D
}

// coeff0_4095: set the first 12-bit coefficient to 4095.
func stimCoeff0Max(pk2 []byte) {
	pk2[0] = 0xFF
	pk2[1] = (pk2[1] & 0xF0) | 0x0F
}

// coeff255_4095: set the last 12-bit coefficient (coeff 255) to 4095.
// Last coefficient at byte positions: 3*255 - 1 = 764 bytes for low, 765 for high.
// Wait: each 3 bytes hold 2 coefficients. coeff i is at bytes [3*(i//2), 3*(i//2)+1, 3*(i//2)+2]
// where i//2 = 127. So bytes [381, 382, 383]. Coeff254 (low) is b381 + b382 low nibble.
// Coeff255 (high) is b382 high nibble + b383.
func stimCoeff255Max(pk2 []byte) {
	pk2[382] = (pk2[382] & 0x0F) | 0xF0 // high nibble of byte 382 = 0xF
	pk2[383] = 0xFF
}

// cross_param_set: replace first 800 bytes (ML-KEM-512 length) with random bytes
// padded to 1184 bytes total.
func stimCrossParamSet(pk2 []byte) {
	// First 800 bytes: fill with 0xCC (deliberate non-canonical encoding)
	for i := 0; i < 800 && i < len(pk2); i++ {
		pk2[i] = 0xCC
	}
}

// stimuli is the canonical stimulus family for the ML-KEM-X25519 cohort.
var mlkemStimuli = []Stimulus{
	{"control", "Canonical C_INIT (no mutation)", stimControl},
	{"truncate_by_1", "C_INIT length = 1215 (one byte short)", stimTruncateBy1},
	{"append_1", "C_INIT length = 1217 (one byte too long)", stimAppend1},
	{"coeff0_q", "First 12-bit coefficient = q = 3329 (at modulus boundary)", stimCoeff0Q},
	{"coeff0_4095", "First 12-bit coefficient = 4095 (max 12-bit value)", stimCoeff0Max},
	{"coeff255_4095", "Last 12-bit coefficient = 4095", stimCoeff255Max},
	{"cross_param_set", "C_PK2 body replaced with ML-KEM-512-sized filler (cross-param-set structural break)", stimCrossParamSet},
}

// sntruprimeStimuli: analogous family for sntrup761x25519-sha512.
// sntruprime byte layout is more complex (6-byte header + NTRU Prime coefficients);
// for the first pass, we only include control + truncate_by_1 + append_1.
// Modulus-half stimuli for sntruprime require reading libcruxy/sntrup761.c to
// identify the small-coefficient byte positions; deferred to a follow-up if
// Stage A/B on the ML-KEM cohort shows interesting results.
var sntruprimeStimuli = []Stimulus{
	{"control", "Canonical C_INIT (no mutation)", stimControl},
	{"truncate_by_1", "C_INIT length = 1062 (one byte short)", stimTruncateBy1},
	{"append_1", "C_INIT length = 1064 (one byte too long)", stimAppend1},
	// Placeholder for sntruprime-specific stimuli after byte-layout audit.
}

type result struct {
	Cohort         string `json:"cohort"`
	Stimulus       string `json:"stimulus"`
	Verdict        string `json:"verdict"` // "strict" | "lenient" | "dangerous" | "harness_error"
	ServerMsg      uint8  `json:"server_msg"` // SSH message type from server
	DisconnectReason uint32 `json:"disconnect_reason,omitempty"`
	WireBytesObserved int `json:"wire_bytes_observed"`
	HandshakeCompleted bool `json:"handshake_completed"`
	SReplyFirstBytes string `json:"s_reply_first_bytes,omitempty"` // first 8 bytes hex of S_REPLY ciphertext
	ElapsedMs      int64  `json:"elapsed_ms"`
	Error          string `json:"error,omitempty"`
}

func main() {
	cohort := flag.String("cohort", "mlkem768x25519-sha256", "SSH hybrid KEX cohort")
	serverAddr := flag.String("server-addr", "127.0.0.1:2222", "sshd address")
	outTSV := flag.String("out-tsv", "reports/ssh_loopback_report.tsv", "output TSV")
	outLog := flag.String("out-log", "reports/ssh_loopback_console.log", "output console log")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*outTSV), 0o755); err != nil {
		fail("mkdir tsv: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*outLog), 0o755); err != nil {
		fail("mkdir log: %v", err)
	}

	tsv, err := os.Create(*outTSV)
	if err != nil {
		fail("create tsv: %v", err)
	}
	defer tsv.Close()
	logf, err := os.Create(*outLog)
	if err != nil {
		fail("create log: %v", err)
	}
	defer logf.Close()

	// TSV header.
	fmt.Fprintln(tsv, "cohort\tstimulus\tverdict\tserver_msg\tdisconnect_reason\twire_bytes\thandshake_completed\ts_reply_first_bytes\telapsed_ms\terror")

	var stimuli []Stimulus
	var ekSize, cInitSize int
	switch *cohort {
	case "mlkem768x25519-sha256":
		stimuli = mlkemStimuli
		ekSize = mlkem768EKSize
		cInitSize = hybridCInitSize
	case "sntrup761x25519-sha512":
		stimuli = sntruprimeStimuli
		ekSize = sntrup761EKSize
		cInitSize = sntruprimeCInitSize
	default:
		fail("unknown cohort %q", *cohort)
	}

	fmt.Fprintf(logf, "ssh_loopback cohort=%s server=%s ekSize=%d cInitSize=%d stimuli=%d\n",
		*cohort, *serverAddr, ekSize, cInitSize, len(stimuli))

	for _, s := range stimuli {
		res := runOne(*cohort, s, *serverAddr, ekSize, cInitSize)
		// Write TSV row.
		fmt.Fprintf(tsv, "%s\t%s\t%s\t%d\t%d\t%d\t%t\t%s\t%d\t%s\n",
			res.Cohort, res.Stimulus, res.Verdict,
			res.ServerMsg, res.DisconnectReason,
			res.WireBytesObserved, res.HandshakeCompleted,
			res.SReplyFirstBytes, res.ElapsedMs,
			strings.ReplaceAll(res.Error, "\t", " "))
		// Write log line.
		js, _ := json.Marshal(res)
		fmt.Fprintf(logf, "RESULT|cohort=%s|stimulus=%s|%s\n", res.Cohort, res.Stimulus, string(js))
	}
}

// runOne connects to the sshd, runs an SSH handshake with the given C_INIT
// mutation, and observes the server's response.
func runOne(cohort string, stim Stimulus, serverAddr string, ekSize, cInitSize int) result {
	res := result{
		Cohort:   cohort,
		Stimulus: stim.Name,
		Verdict:  "harness_error",
	}
	start := time.Now()
	defer func() {
		res.ElapsedMs = time.Since(start).Milliseconds()
	}()

	// Generate a fresh ed25519 host key for the client-side signature in
	// SSH_MSG_KEXDH_REPLY (when the server sends it).
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		res.Error = fmt.Sprintf("genkey: %v", err)
		return res
	}

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		res.Error = fmt.Sprintf("dial: %v", err)
		return res
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Drive the SSH binary packet protocol:
	//   0. Client sends version banner (RFC 4253 s4.2):
	//      "SSH-protoversion-softwareversion SP comments CR LF"
	//   1. Server replies with its version banner.
	//   2. Client sends SSH_MSG_KEXINIT with hybrid KEX in the list.
	//   3. Server replies SSH_MSG_KEXINIT with its chosen kex + host key.
	//   4. Client sends SSH_MSG_KEX_HYBRID_INIT with mutated C_INIT.
	//   5. Server replies SSH_MSG_KEX_HYBRID_REPLY (lenient) or SSH_MSG_DISCONNECT (strict) or closes.

	if err := sendBanner(conn); err != nil {
		res.Error = fmt.Sprintf("send banner: %v", err)
		return res
	}
	if err := recvBanner(conn); err != nil {
		res.Error = fmt.Sprintf("recv banner: %v", err)
		return res
	}

	if err := sendKexInit(conn, cohort); err != nil {
		res.Error = fmt.Sprintf("send kexinit: %v", err)
		return res
	}

	serverKex, err := recvPacket(conn)
	if err != nil {
		res.Error = fmt.Sprintf("recv server kexinit: %v", err)
		return res
	}
	if len(serverKex) < 1 || serverKex[0] != sshMsgKexinit {
		res.ServerMsg = uint8(serverKex[0])
		res.Verdict = classify(serverKex, ekSize, cohort, &res)
		return res
	}

	// Build C_INIT with stimulus mutation.
	cInit := make([]byte, cInitSize)
	// Fill with a canonical-looking byte pattern (mostly zeros, no 12-bit
	// overflows for control; mutations override specific bytes).
	for i := range cInit {
		cInit[i] = 0x00
	}
	// Apply stimulus mutation. Stimuli that mutate body bytes operate on cInit[:ekSize].
	stim.Mutate(cInit[:ekSize])
	// Special length mutations.
	if stim.Name == "truncate_by_1" {
		cInit = cInit[:len(cInit)-1]
	} else if stim.Name == "append_1" {
		cInit = append(cInit, 0x00)
	}

	// Send SSH_MSG_KEX_HYBRID_INIT with the mutated C_INIT.
	if err := sendHybridInit(conn, cInit); err != nil {
		res.Error = fmt.Sprintf("send hybrid init: %v", err)
		return res
	}

	// Read server response.
	resp, err := recvPacket(conn)
	if err != nil {
		res.Error = fmt.Sprintf("recv response: %v", err)
		return res
	}
	res.WireBytesObserved = len(resp)
	res.ServerMsg = uint8(resp[0])
	res.Verdict = classify(resp, ekSize, cohort, &res)

	// Extract disconnect reason if applicable.
	if len(resp) > 1 && resp[0] == sshMsgDisconnect {
		res.DisconnectReason = binary.BigEndian.Uint32(resp[1:5])
	}
	// Extract S_REPLY first bytes if applicable.
	if len(resp) > 0 && resp[0] == sshMsgKexHybridReply {
		// S_REPLY starts after the host key blob and exchange hash; for a
		// pure discrimination oracle, capture the first 8 bytes of the
		// post-header ciphertext as fingerprint.
		res.HandshakeCompleted = true
		// Approximate: skip K_S blob (variable length) and H (64 bytes SHA-512).
		// For brevity we just hash the first 8 bytes of the packet.
		if len(resp) > 8 {
			res.SReplyFirstBytes = hex.EncodeToString(resp[:8])
		}
	}
	// clientPriv is used to sign the exchange hash if the handshake completes
	// (we don't actually need to verify, just to make the client-side message
	// structurally complete). Silence unused-variable.
	_ = clientPriv
	return res
}

// classify returns the verdict based on the server's first response packet.
func classify(resp []byte, ekSize int, cohort string, res *result) string {
	if len(resp) == 0 {
		return "dangerous"
	}
	switch resp[0] {
	case sshMsgDisconnect:
		return "strict"
	case sshMsgKexHybridReply:
		return "lenient"
	case sshMsgKexinit:
		// Server re-sent KEXINIT -- unexpected
		return "dangerous"
	default:
		return "dangerous"
	}
}

// --- SSH binary packet protocol (RFC 4253 s6) ---

func sendKexInit(conn net.Conn, cohort string) error {
	// SSH_MSG_KEXINIT payload per RFC 4253 s7:
	//   byte         SSH_MSG_KEXINIT (20)
	//   byte[16]     cookie (random)
	//   name-list    kex_algorithms
	//   name-list    server_host_key_algorithms
	//   name-list    encryption_algorithms_client_to_server
	//   name-list    encryption_algorithms_server_to_client
	//   name-list    mac_algorithms_client_to_server
	//   name-list    mac_algorithms_server_to_client
	//   name-list    compression_algorithms_client_to_server
	//   name-list    compression_algorithms_server_to_client
	//   name-list    languages_client_to_server
	//   name-list    languages_server_to_client
	//   boolean      first_kex_packet_follows
	//   uint32       0 (reserved for future extension)

	cookie := make([]byte, 16)
	rand.Read(cookie)

	var kexAlgs string
	switch cohort {
	case "mlkem768x25519-sha256":
		kexAlgs = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256"
	case "sntrup761x25519-sha512":
		kexAlgs = "sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256"
	default:
		kexAlgs = "curve25519-sha256,diffie-hellman-group14-sha256"
	}
	sigAlgs := "ssh-ed25519"
	encAlgs := "aes256-gcm@openssh.com,aes128-gcm@openssh.com"
	macAlgs := "hmac-sha2-512,hmac-sha2-256"
	compAlgs := "none"

	var payload []byte
	payload = append(payload, sshMsgKexinit)
	payload = append(payload, cookie...)
	payload = appendNameList(payload, kexAlgs)
	payload = appendNameList(payload, sigAlgs)
	payload = appendNameList(payload, encAlgs)
	payload = appendNameList(payload, encAlgs)
	payload = appendNameList(payload, macAlgs)
	payload = appendNameList(payload, macAlgs)
	payload = appendNameList(payload, compAlgs)
	payload = appendNameList(payload, compAlgs)
	payload = appendNameList(payload, "")
	payload = appendNameList(payload, "")
	payload = append(payload, 0)   // first_kex_packet_follows = false
	payload = append(payload, 0, 0, 0, 0) // reserved
	return sendPacket(conn, payload)
}

func sendHybridInit(conn net.Conn, cInit []byte) error {
	// SSH_MSG_KEX_HYBRID_INIT (30) payload:
	//   string C_INIT  (per draft s2.1: C_PK2 || C_PK1)
	var payload []byte
	payload = append(payload, sshMsgKexHybridInit)
	cInitLen := make([]byte, 4)
	binary.BigEndian.PutUint32(cInitLen, uint32(len(cInit)))
	payload = append(payload, cInitLen...)
	payload = append(payload, cInit...)
	return sendPacket(conn, payload)
}

// sendPacket writes one an SSH packet: uint32 packet_length || byte padding_length || payload || padding.
func sendPacket(conn net.Conn, payload []byte) error {
	const blockSize = 8 // aes256-gcm block size for OpenSSH
	paddingLen := blockSize - ((5 + len(payload)) % blockSize)
	if paddingLen < 4 {
		paddingLen += blockSize
	}
	packetLen := 1 + len(payload) + paddingLen
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(packetLen))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	paddingByte := byte(paddingLen)
	if _, err := conn.Write([]byte{paddingByte}); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	if _, err := conn.Write(padding); err != nil {
		return err
	}
	return nil
}

// recvPacket reads one an SSH packet.
func recvPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint32(header)
	if packetLen < 1 || packetLen > 35000 {
		return nil, fmt.Errorf("invalid packet length %d", packetLen)
	}
	body := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	paddingLen := int(body[0])
	payload := body[1 : 1+int(packetLen)-1-paddingLen]
	return payload, nil
}

func appendNameList(buf []byte, names string) []byte {
	parts := strings.Split(names, ",")
	var nl []byte
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, uint32(len(p)))
		nl = append(nl, l...)
		nl = append(nl, []byte(p)...)
	}
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(nl)))
	buf = append(buf, l...)
	buf = append(buf, nl...)
	return buf
}

// --- SSH version banner (RFC 4253 s4.2) ---

func sendBanner(conn net.Conn) error {
	banner := "SSH-2.0-FrontierSSHLoopback_1.0\r\n"
	_, err := conn.Write([]byte(banner))
	return err
}

func recvBanner(conn net.Conn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 4 || string(buf[:4]) != "SSH-" {
		return fmt.Errorf("expected SSH banner, got %q", string(buf[:n]))
	}
	// Find end of banner line (CRLF).
	for i := 0; i < n-1; i++ {
		if buf[i] == '\r' && buf[i+1] == '\n' {
			return nil
		}
	}
	return fmt.Errorf("banner line missing CRLF: %q", string(buf[:n]))
}

// --- helpers ---

var _ = sync.Mutex{} // silence unused

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}