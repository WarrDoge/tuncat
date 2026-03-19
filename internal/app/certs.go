package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type PFXCredentials struct {
	Certificate tls.Certificate
	RootCAs     *x509.CertPool
}

func loadPFXCredentials(pfxPath, password string) (*PFXCredentials, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("read pfx %s: %w", pfxPath, err)
	}

	privateKey, leaf, chain, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("decode pfx %s: %w", pfxPath, err)
	}

	tlsCert := tls.Certificate{
		Certificate: make([][]byte, 0, 1+len(chain)),
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}
	tlsCert.Certificate = append(tlsCert.Certificate, leaf.Raw)
	for _, c := range chain {
		tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, c := range chain {
		rootCAs.AddCert(c)
	}

	return &PFXCredentials{
		Certificate: tlsCert,
		RootCAs:     rootCAs,
	}, nil
}
