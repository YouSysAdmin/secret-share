package tlsutils

import "testing"

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"none (empty)", Config{}, false},
		{"none explicit", Config{Mode: ModeNone}, false},
		{"manual ok", Config{Mode: ModeManual, Cert: "c.pem", Key: "k.pem"}, false},
		{"manual missing key", Config{Mode: ModeManual, Cert: "c.pem"}, true},
		{"self ok", Config{Mode: ModeSelf, FQDN: "share.example.com"}, false},
		{"self ed25519 ok", Config{Mode: ModeSelf, FQDN: "x", Alg: "ed25519"}, false},
		{"self missing fqdn", Config{Mode: ModeSelf}, true},
		{"self bad alg", Config{Mode: ModeSelf, FQDN: "x", Alg: "dsa"}, true},
		{"acme ok", Config{Mode: ModeACME, ACME: ACMEBlock{Hosts: []string{"x"}}}, false},
		{"acme no hosts", Config{Mode: ModeACME}, true},
		{"unknown mode", Config{Mode: "self-signed"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateConfig(tt.cfg); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateConfig() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildNoneReturnsNil(t *testing.T) {
	cfg, err := Build(Config{Mode: ModeNone})
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatal("ModeNone should yield a nil *tls.Config (plain HTTP)")
	}
}

func TestBuildSelfSigned(t *testing.T) {
	for _, alg := range []string{"", "rsa", "ed25519"} {
		cfg, err := Build(Config{Mode: ModeSelf, FQDN: "share.example.com", Alg: alg})
		if err != nil {
			t.Fatalf("alg %q: %v", alg, err)
		}
		if cfg == nil || len(cfg.Certificates) != 1 {
			t.Fatalf("alg %q: expected one generated certificate", alg)
		}
		if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
			t.Fatalf("alg %q: want MinVersion TLS1.2", alg)
		}
	}
}
