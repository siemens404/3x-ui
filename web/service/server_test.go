package service

import "testing"

func TestNormalizeVlessAuthKeyType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    vlessAuthKeyType
		wantErr bool
	}{
		{name: "x25519 canonical", input: "x25519", want: vlessAuthKeyTypeX25519},
		{name: "x25519 label", input: "X25519, not Post-Quantum", want: vlessAuthKeyTypeX25519},
		{name: "mlkem canonical", input: "mlkem768", want: vlessAuthKeyTypeMLKEM768},
		{name: "mlkem label", input: "ML-KEM-768, Post-Quantum", want: vlessAuthKeyTypeMLKEM768},
		{name: "unknown", input: "rsa", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeVlessAuthKeyType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParseVlessEncOutput(t *testing.T) {
	output := `Authentication: X25519, non post-quantum
"decryption": "none",
"encryption": "x25519:client-public-key"

Authentication: ML-KEM-768, Post-Quantum
"decryption": "mlkem768:server-seed",
"encryption": "mlkem768:client-kem"
`

	auths, err := parseVlessEncOutput(output)
	if err != nil {
		t.Fatalf("parseVlessEncOutput error: %v", err)
	}
	if len(auths) != 2 {
		t.Fatalf("expected 2 auth blocks, got %d", len(auths))
	}

	if auths[0].KeyType != string(vlessAuthKeyTypeX25519) {
		t.Fatalf("first block keyType: want %q, got %q", vlessAuthKeyTypeX25519, auths[0].KeyType)
	}
	if auths[0].Encryption != "x25519:client-public-key" {
		t.Fatalf("first block encryption parsed incorrectly: %q", auths[0].Encryption)
	}

	if auths[1].KeyType != string(vlessAuthKeyTypeMLKEM768) {
		t.Fatalf("second block keyType: want %q, got %q", vlessAuthKeyTypeMLKEM768, auths[1].KeyType)
	}
	if auths[1].Decryption != "mlkem768:server-seed" {
		t.Fatalf("second block decryption parsed incorrectly: %q", auths[1].Decryption)
	}
}

func TestFilterVlessEncAuth(t *testing.T) {
	auths := []vlessEncAuth{
		{Label: "X25519", KeyType: string(vlessAuthKeyTypeX25519), Decryption: "none", Encryption: "x25519:client"},
		{Label: "ML-KEM-768", KeyType: string(vlessAuthKeyTypeMLKEM768), Decryption: "mlkem768:seed", Encryption: "mlkem768:client"},
	}

	x25519Only, err := filterVlessEncAuth(auths, "x25519")
	if err != nil {
		t.Fatalf("filter x25519 error: %v", err)
	}
	if len(x25519Only) != 1 {
		t.Fatalf("expected 1 x25519 auth, got %d", len(x25519Only))
	}
	if x25519Only[0].KeyType != string(vlessAuthKeyTypeX25519) {
		t.Fatalf("expected x25519 keyType, got %q", x25519Only[0].KeyType)
	}
	if x25519Only[0].Encryption == "mlkem768:client" || x25519Only[0].Decryption == "mlkem768:seed" {
		t.Fatalf("x25519 result contains mlkem material: %+v", x25519Only[0])
	}

	mlkemOnly, err := filterVlessEncAuth(auths, "mlkem768")
	if err != nil {
		t.Fatalf("filter mlkem error: %v", err)
	}
	if len(mlkemOnly) != 1 {
		t.Fatalf("expected 1 mlkem auth, got %d", len(mlkemOnly))
	}
	if mlkemOnly[0].KeyType != string(vlessAuthKeyTypeMLKEM768) {
		t.Fatalf("expected mlkem keyType, got %q", mlkemOnly[0].KeyType)
	}

	if _, err := filterVlessEncAuth(auths, "unknown"); err == nil {
		t.Fatalf("expected unknown key type error")
	}
}
