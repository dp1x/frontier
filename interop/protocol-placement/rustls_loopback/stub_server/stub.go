// Command stub_rustls_server is a Go fallback used to validate the harness
// end-to-end without requiring an aws-lc-rs build. It is NOT the real
// rustls_server and is not committed as the deliverable. We replace it with
// the real Rust binary built via cargo in the GHA workflow.
//
// The stub uses Go's stdlib crypto/tls (which already enforces s7.2 per
// obs-2026-0011), so the per-variant behaviour is essentially "what Go does"
// not "what aws-lc-rs does" -- but it's good enough to smoke-test the
// harness plumbing (TCP loopback spawn, mitator insertion, JSON RESULT
// parsing, TSV emission).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	port, err := strconv.Atoi(os.Getenv("RUSTLS_LOOPBACK_PORT"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad port:", err)
		os.Exit(2)
	}
	mode := os.Getenv("RUSTLS_LOOPBACK_MODE")
	variantNum := os.Getenv("RUSTLS_LOOPBACK_VARIANT_NUM")
	fmt.Printf("META|stub=go-stdlib|crypto=Go-fips140-ML-KEM|mode=%s variant=%s port=%d\n",
		mode, variantNum, port)

	cert := buildCert()
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(2)
	}
	fmt.Println("READY")
	conn, err := ln.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "accept:", err)
		os.Exit(2)
	}
	ln.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	sc := tls.Server(conn, cfg)
	hs_err := sc.Handshake()

	ok := "true"
	errStr := ""
	alert := ""
	if hs_err != nil {
		ok = "false"
		errStr = hs_err.Error()
		alert = hs_err.Error()
	}
	fmt.Printf("RESULT|{\"ok\":%s,\"variant\":\"%s\",\"error\":\"%s\",\"alert\":\"%s\"}\n",
		ok, mode, errStr, alert)
	fmt.Println("DONE")
	conn.Close()
}

func buildCert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "stub-rustls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}