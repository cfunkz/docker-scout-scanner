package tlsgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// RemoteCerts writes a private CA plus one server and one client certificate
// for a remote agent, using Docker's usual file names:
//
//	out/agent/   ca.pem server-cert.pem server-key.pem   (copy to the remote host)
//	out/scanner/ ca.pem cert.pem key.pem                 (DOCKER_CERT_PATH for the scanner)
//
// The CA key is never written, so nobody can mint more certificates for this
// pair. Run it again to rotate.
func RemoteCerts(out string, hosts []string, years int) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "docker-scout-scanner agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ = x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leaf := func(cn string, usage x509.ExtKeyUsage, sans []string) (certPEM, keyPEM []byte, err error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		tpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     ca.NotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		for _, s := range sans {
			if ip := net.ParseIP(s); ip != nil {
				tpl.IPAddresses = append(tpl.IPAddresses, ip)
			} else {
				tpl.DNSNames = append(tpl.DNSNames, s)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		kb, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
	}
	sc, sk, err := leaf(hosts[0], x509.ExtKeyUsageServerAuth, hosts)
	if err != nil {
		return err
	}
	cc, ck, err := leaf("docker-scout-scanner", x509.ExtKeyUsageClientAuth, nil)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"agent/ca.pem": caPEM, "agent/server-cert.pem": sc, "agent/server-key.pem": sk,
		"scanner/ca.pem": caPEM, "scanner/cert.pem": cc, "scanner/key.pem": ck,
	}
	for name, b := range files {
		p := filepath.Join(out, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if filepath.Ext(name) == ".pem" && (filepath.Base(name) == "key.pem" || filepath.Base(name) == "server-key.pem") {
			mode = 0o600
		}
		if err := os.WriteFile(p, b, mode); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
