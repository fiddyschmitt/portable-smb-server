package md4

import (
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

// RFC 1320 appendix A.5 test vectors.
func TestVectors(t *testing.T) {
	vectors := map[string]string{
		"":                           "31d6cfe0d16ae931b73c59d7e0c089c0",
		"a":                          "bde52cb31de33e46245e05fbdbd6fb24",
		"abc":                        "a448017aaf21d8525fc10ae87aa6729d",
		"message digest":             "d9130a8164549fe818874806e1c7014b",
		"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":                   "043f8582f241db351ce627e153e7f0e4",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
	}
	for in, want := range vectors {
		h := New()
		h.Write([]byte(in))
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			t.Errorf("md4(%q) = %s, want %s", in, got, want)
		}
	}
}

// NT-hash of "password" per MS-NLMP: MD4(UTF-16LE("password")).
func TestNTHashVector(t *testing.T) {
	h := New()
	for _, r := range utf16.Encode([]rune("password")) {
		h.Write([]byte{byte(r), byte(r >> 8)})
	}
	const want = "8846f7eaee8fb117ad06bdd830b7586c"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("ntHash(password) = %s, want %s", got, want)
	}
}
