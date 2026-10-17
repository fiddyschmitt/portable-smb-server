package smb

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"math/rand"
	"testing"
)

// TestAESCMACVectors checks aesCMAC against the test vectors of RFC 4493 section 4 (AES-128).
func TestAESCMACVectors(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	msg, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		if got := hex.EncodeToString(aesCMAC(key, msg[:tc.n])); got != tc.want {
			t.Errorf("CMAC of %d bytes = %s, want %s", tc.n, got, tc.want)
		}
	}
}

// TestAESCMACMatchesReference compares the chained aesCMAC with the plain block-at-a-time one
// across lengths that straddle its chunking: around a block, a chunk, and a 1 MiB response.
func TestAESCMACMatchesReference(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i*3 + 1)
	}
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1000,
		cmacChunk - 16, cmacChunk - 1, cmacChunk, cmacChunk + 1, cmacChunk + 16, 3*cmacChunk + 7,
		1 << 20, 1<<20 + 64 + 16} {
		msg := make([]byte, n)
		rng.Read(msg)
		if got, want := aesCMAC(key, msg), aesCMACReference(key, msg); !bytes.Equal(got, want) {
			t.Errorf("%d bytes: chained CMAC %x, reference %x", n, got, want)
		}
	}
}

// aesCMACReference is RFC 4493 written out block by block: the oracle for aesCMAC.
func aesCMACReference(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	const bs = 16
	xorRef := func(dst, a, b []byte) {
		for i := range dst {
			dst[i] = a[i] ^ b[i]
		}
	}
	mulX := func(in []byte) []byte {
		out := make([]byte, len(in))
		var carry byte
		for i := len(in) - 1; i >= 0; i-- {
			out[i] = in[i]<<1 | carry
			carry = in[i] >> 7
		}
		if carry != 0 {
			out[len(out)-1] ^= 0x87
		}
		return out
	}
	subkey := make([]byte, bs)
	block.Encrypt(subkey, subkey)
	k1 := mulX(subkey)
	k2 := mulX(k1)
	full, rem := len(msg)/bs, len(msg)%bs
	if rem == 0 && full > 0 {
		full--
		rem = bs
	}
	x, tmp, last := make([]byte, bs), make([]byte, bs), make([]byte, bs)
	for i := 0; i < full; i++ {
		xorRef(tmp, x, msg[i*bs:i*bs+bs])
		block.Encrypt(x, tmp)
	}
	copy(last, msg[full*bs:])
	if rem == bs {
		xorRef(last, last, k1)
	} else {
		last[rem] = 0x80
		xorRef(last, last, k2)
	}
	xorRef(tmp, x, last)
	block.Encrypt(x, tmp)
	return x
}

func benchmarkCMAC(b *testing.B, f func(key, msg []byte) []byte) {
	key := make([]byte, 16)
	msg := make([]byte, 1<<20+64+16) // a signed 1 MiB READ response
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f(key, msg)
	}
}

func BenchmarkAESCMAC1MiB(b *testing.B)          { benchmarkCMAC(b, aesCMAC) }
func BenchmarkAESCMAC1MiBReference(b *testing.B) { benchmarkCMAC(b, aesCMACReference) }
