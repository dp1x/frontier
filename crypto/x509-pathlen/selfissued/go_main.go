package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return x509.ParseCertificate(b)
	}
	return x509.ParseCertificate(block.Bytes)
}

func certSHA256(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return fmt.Sprintf("%x", h)
}

func main() {
	base := `R:\x509-selfissued\certs`
	if len(os.Args) > 1 {
		base = os.Args[1]
	}
	load := func(name string) *x509.Certificate {
		c, err := loadCert(filepath.Join(base, name+".pem"))
		if err != nil {
			fmt.Println("LOAD ERR", name, err)
			os.Exit(1)
		}
		return c
	}
	R := load("R")
	C0 := load("C0")
	C2 := load("C2")
	IC := load("IC")
	Snone := load("S_none")
	S0 := load("S0")
	S1 := load("S1")
	IS0 := load("IS0")
	IS1 := load("IS1")
	EE1 := load("EE_T1")
	EE2 := load("EE_T2")
	EE3 := load("EE_T3")
	EE4 := load("EE_T4")
	EE5 := load("EE_T5")

	roots := x509.NewCertPool()
	roots.AddCert(R)
	verifyTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	type cas struct {
		name string
		leaf *x509.Certificate
		ints []*x509.Certificate
	}
	cases := []cas{
		{"T1", EE1, []*x509.Certificate{C0}},
		{"T2", EE2, []*x509.Certificate{C0, IC}},
		{"T3", EE3, []*x509.Certificate{C0, Snone}},
		{"T4", EE4, []*x509.Certificate{C2, S0, IS0}},
		{"T5", EE5, []*x509.Certificate{C2, S1, IS1}},
	}
	for _, c := range cases {
		pool := x509.NewCertPool()
		for _, ic := range c.ints {
			pool.AddCert(ic)
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: pool,
			CurrentTime:   verifyTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		chains, err := c.leaf.Verify(opts)
		fmt.Printf("=== %s ===\n", c.name)
		if err != nil {
			fmt.Printf("RESULT: REJECT\nERROR: %v\n", err)
			if ci, ok := err.(x509.CertificateInvalidError); ok {
				fmt.Printf("  Reason: %v\n  Cert: %s\n  CertSHA256: %s\n", ci.Reason, ci.Cert.Subject, certSHA256(ci.Cert))
			}
		} else {
			fmt.Printf("RESULT: ACCEPT\n")
			for i, ch := range chains {
				fmt.Printf("  chain %d:\n", i)
				for _, cert := range ch {
					fmt.Printf("    %s | %s\n", cert.Subject, certSHA256(cert))
				}
			}
		}
	}
}
