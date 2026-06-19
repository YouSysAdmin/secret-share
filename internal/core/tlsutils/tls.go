package tlsutils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	certificateCommonName   = "Self-Signed secret-share"
	certificateOrganization = []string{"secret-share"}
)

type ACME struct {
	Enable   bool
	Email    string
	CacheDir string
	HTTPAddr string
	Hosts    []string
}

type ManualTLS struct {
	CertFile string
	KeyFile  string
}

// AutoTLS starts the HTTP-01 challenge listener and returns a TLS config whose
// certs come from autocert's cache. The listener runs in a background goroutine.
func AutoTLS(ac ACME) *tls.Config {
	if !ac.Enable {
		return nil
	}
	cache := ac.CacheDir
	if cache == "" {
		cache = "certs"
	}
	addr := ac.HTTPAddr
	if addr == "" {
		addr = ":80"
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cache),
		Email:  ac.Email,
	}
	if len(ac.Hosts) > 0 {
		m.HostPolicy = autocert.HostWhitelist(ac.Hosts...)
	}
	go func() {
		// HTTPHandler serves the ACME challenge and forwards everything else to
		// fallback. We 308-redirect every method (308 preserves the method) so a
		// misdirected POST doesn't hit a confusing 405.
		srv := &http.Server{
			Addr:              addr,
			Handler:           m.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
			ReadHeaderTimeout: 10 * time.Second,
		}
		slog.Info("ACME HTTP challenge listener", "addr", addr, "hosts", ac.Hosts)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Don't kill the process - cert issuance fails visibly and the API
			// stays up in the meantime.
			slog.Error("ACME HTTP server failed; cert issuance will not work", "err", err, "addr", addr)
		}
	}()
	return &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

// LoadManualTLS loads an operator-supplied cert + key pair.
func LoadManualTLS(m ManualTLS) (*tls.Config, error) {
	if m.CertFile == "" || m.KeyFile == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

// SelfSignedTLS generates a fresh in-memory cert for fqdn (+ localhost SAN).
// alg = "ed25519" or "rsa" (empty -> rsa).
func SelfSignedTLS(fqdn, alg string) (*tls.Config, error) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "ed25519":
		return selfSignedEd25519(fqdn)
	default:
		return selfSignedRSA(fqdn)
	}
}

func selfSignedRSA(fqdn string) (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: certificateCommonName, Organization: certificateOrganization},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		DNSNames:              []string{fqdn, "localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

func selfSignedEd25519(fqdn string) (*tls.Config, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: certificateCommonName, Organization: certificateOrganization},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{fqdn, "localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}
