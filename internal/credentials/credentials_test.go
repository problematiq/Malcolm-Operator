package credentials

import (
	"strings"
	"testing"
)

func TestMD5CryptMatchesOpenSSL(t *testing.T) {
	// Vectors produced with `openssl passwd -1 -salt <salt> <password>`.
	cases := []struct{ password, salt, want string }{
		{"malcolm", "xhZ5v90R", "$1$xhZ5v90R$qQmoPuMUb1XAKitK0FoqO."},
		{"", "ab", "$1$ab$rn6aQS/o7141mj179E/zA."},
		{`p@ss:w"rd with spaces and a very long passphrase exceeding sixteen bytes`, "saltsalt", "$1$saltsalt$QigLyVwX6vfB7pwk/F6n2."},
	}
	for _, c := range cases {
		got, err := MD5Crypt(c.password, c.salt)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("MD5Crypt(%q, %q) = %q, want %q", c.password, c.salt, got, c.want)
		}
	}
}

func TestMD5CryptRandomSaltVerifies(t *testing.T) {
	h, err := MD5Crypt("secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$1$") || !VerifyMD5Crypt(h, "secret") || VerifyMD5Crypt(h, "wrong") {
		t.Fatalf("unexpected hash behavior: %q", h)
	}
}

func TestHtpasswd(t *testing.T) {
	line, err := Htpasswd("malcolm", "pa$$word")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "malcolm:$2y$") {
		t.Fatalf("unexpected htpasswd line %q", line)
	}
	if !VerifyHtpasswd(line, "malcolm", "pa$$word") || VerifyHtpasswd(line, "malcolm", "nope") || VerifyHtpasswd(line, "other", "pa$$word") {
		t.Fatal("htpasswd verification failed")
	}
	// The Helm chart's default htpass_cred (malcolm:malcolm) must verify too.
	if !VerifyHtpasswd("malcolm:$2y$05$G68ph4JvfyQu77luvKG77OvuKgeEgwPPtJk07L5iqwkifrLxRo1qi", "malcolm", "malcolm") {
		t.Fatal("failed to verify a $2y$ hash produced by htpasswd")
	}
	if _, err := Htpasswd("bad:user", "x"); err == nil {
		t.Fatal("expected error for username containing ':'")
	}
}

func TestRandom(t *testing.T) {
	a, err := Random(32)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Random(32)
	if len(a) != 32 || a == b {
		t.Fatalf("unexpected random output %q %q", a, b)
	}
	for _, c := range a {
		if !strings.ContainsRune(alphanumeric, c) {
			t.Fatalf("non-alphanumeric character %q", c)
		}
	}
}
