package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"strings"
	"sync"

	"portable-smb-server/internal/md4" // MD4 is required by the NTLM protocol
)

// NTLMSSP negotiate flag for session key exchange.
const ntlmNegotiateKeyExch uint32 = 0x40000000

// NTLMSSP negotiate flag indicating the message carries an 8-byte OS Version
// field after the negotiate flags. Windows clients set this; we read the major
// version to spot a Windows client (which can't use guest) and warn.
const ntlmNegotiateVersion uint32 = 0x02000000

// ntHash returns the NTLM hash of a password: MD4(UTF-16LE(password)).
func ntHash(password string) []byte {
	h := md4.New()
	_, _ = h.Write(stringToUTF16le(password))
	return h.Sum(nil)
}

// ntowfv2 computes the NTLMv2 one-way function:
// HMAC-MD5(NTHash, UPPERCASE(user) + domain).
func ntowfv2(user, password, domain string) []byte {
	mac := hmac.New(md5.New, ntHash(password))
	_, _ = mac.Write(stringToUTF16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

// validateNTLMv2 checks an NTLMv2 NtChallengeResponse (NTProofStr followed by
// the client blob) against the proof computed from responseKeyNT (the NTOWFv2)
// and the server challenge.
func validateNTLMv2(responseKeyNT []byte, serverChallenge [8]byte, ntResponse []byte) bool {
	if len(ntResponse) < 16 {
		return false
	}
	proof := ntResponse[:16]
	blob := ntResponse[16:]
	mac := hmac.New(md5.New, responseKeyNT)
	_, _ = mac.Write(serverChallenge[:])
	_, _ = mac.Write(blob)
	return hmac.Equal(proof, mac.Sum(nil))
}

// exportedSessionKey recovers the NTLMv2 session key the client derived, used
// as the basis for SMB signing keys. ntProofStr is the first 16 bytes of the
// NtChallengeResponse.
func exportedSessionKey(responseKeyNT, ntProofStr []byte, flags uint32, encRandomSessionKey []byte) []byte {
	mac := hmac.New(md5.New, responseKeyNT)
	_, _ = mac.Write(ntProofStr)
	keyExchangeKey := mac.Sum(nil) // SessionBaseKey == KeyExchangeKey for NTLMv2
	if flags&ntlmNegotiateKeyExch != 0 && len(encRandomSessionKey) == 16 {
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err == nil {
			out := make([]byte, 16)
			cipher.XORKeyStream(out, encRandomSessionKey)
			return out
		}
	}
	return keyExchangeKey
}

// kdf is the SP 800-108 counter-mode KDF used by SMB 3.x key derivation
// (h=256, r=32, L=128).
func kdf(ki, label, context []byte) []byte {
	h := hmac.New(sha256.New, ki)
	_, _ = h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	_, _ = h.Write(label)
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(context)
	_, _ = h.Write([]byte{0x00, 0x00, 0x00, 0x80})
	return h.Sum(nil)[:16]
}

// ntlmAuthenticate holds the fields we need from an NTLMSSP AUTHENTICATE
// (Type 3) message.
type ntlmAuthenticate struct {
	user          string
	domain        string
	ntResponse    []byte
	flags         uint32
	encSessionKey []byte
	osMajor       byte // NTLMSSP Version ProductMajorVersion (0 if no Version field)
}

// parseNTLMAuthenticate parses an NTLMSSP AUTHENTICATE (Type 3) message
// ([MS-NLMP] 2.2.1.3). It assumes Unicode (UTF-16LE) names, which our CHALLENGE
// negotiates.
func parseNTLMAuthenticate(msg []byte) (ntlmAuthenticate, bool) {
	if len(msg) < 64 || string(msg[0:8]) != string(ntlmSignature) || le.Uint32(msg[8:12]) != ntlmTypeAuthenticate {
		return ntlmAuthenticate{}, false
	}
	field := func(off int) []byte {
		length := int(le.Uint16(msg[off : off+2]))
		start := int(le.Uint32(msg[off+4 : off+8]))
		if length == 0 || start < 0 || start+length > len(msg) {
			return nil
		}
		return msg[start : start+length]
	}
	flags := le.Uint32(msg[60:64]) // NegotiateFlags
	var osMajor byte
	// The 8-byte Version field follows the negotiate flags when NEGOTIATE_VERSION
	// is set; its first byte is ProductMajorVersion.
	if flags&ntlmNegotiateVersion != 0 && len(msg) >= 65 {
		osMajor = msg[64]
	}
	return ntlmAuthenticate{
		domain:        utf16leToString(field(28)), // DomainNameFields
		user:          utf16leToString(field(36)), // UserNameFields
		ntResponse:    field(20),                  // NtChallengeResponseFields
		encSessionKey: field(52),                  // EncryptedRandomSessionKeyFields
		flags:         flags,
		osMajor:       osMajor,
	}, true
}

// signMessage signs an SMB2 message in place using the given signing key and
// the algorithm for the negotiated dialect (HMAC-SHA256 for 2.x, AES-CMAC for
// 3.x). The signature covers the whole message with the signature field zeroed
// and the SMB2_FLAGS_SIGNED flag set.
func signMessage(signKey []byte, dialect uint16, msg []byte) {
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}
	le.PutUint32(msg[16:20], le.Uint32(msg[16:20])|flagsSigned)
	var sig []byte
	switch dialect {
	case dialect300, dialect302:
		sig = aesCMAC(signKey, msg)
	default:
		mac := hmac.New(sha256.New, signKey)
		_, _ = mac.Write(msg)
		sig = mac.Sum(nil)
	}
	copy(msg[48:64], sig[:16])
}

// verifyMessage reports whether a signed inbound SMB2 message carries a valid
// signature for the given key and dialect. It recomputes the signature over the
// message with the signature field zeroed (as the sender did) and compares it in
// constant time, restoring the field before returning.
func verifyMessage(signKey []byte, dialect uint16, msg []byte) bool {
	if len(msg) < 64 {
		return false
	}
	var received [16]byte
	copy(received[:], msg[48:64])
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}
	var sig []byte
	switch dialect {
	case dialect300, dialect302:
		sig = aesCMAC(signKey, msg)
	default:
		mac := hmac.New(sha256.New, signKey)
		_, _ = mac.Write(msg)
		sig = mac.Sum(nil)
	}
	copy(msg[48:64], received[:])
	return hmac.Equal(received[:], sig[:16])
}

// cmacChunk is how much of a message goes through the CBC encrypter per call. The chain state is
// carried from one call to the next as its IV, so the scratch output never has to be the size of
// the message.
const cmacChunk = 64 << 10

var cmacScratch = sync.Pool{New: func() any { b := make([]byte, cmacChunk); return &b }}

// aesCMAC computes the AES-CMAC of msg (RFC 4493 / NIST SP 800-38B). CMAC is CBC-MAC with the
// last block tweaked by a subkey, so every whole block before the last goes through the standard
// library's CBC encrypter -- its tightest AES chain -- and only the last block is done by hand. A
// block-at-a-time loop here, with its own XOR and a cipher call per block, was nearly half the
// server's CPU under a Windows client, which signs every message, 1 MiB READ responses included.
func aesCMAC(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	const bs = 16
	var l, k1, k2 [bs]byte
	block.Encrypt(l[:], l[:]) // L = AES(K, 0)
	gfMulX(&k1, &l)
	gfMulX(&k2, &k1)

	// The whole blocks before the last one (which may be partial, or the only one).
	full := len(msg) / bs
	rem := len(msg) % bs
	if rem == 0 && full > 0 {
		full--
		rem = bs
	}
	var x [bs]byte // the chain state: the last ciphertext block so far
	if full > 0 {
		scratchP := cmacScratch.Get().(*[]byte)
		scratch := *scratchP
		for off, end := 0, full*bs; off < end; {
			n := end - off
			if n > len(scratch) {
				n = len(scratch)
			}
			cipher.NewCBCEncrypter(block, x[:]).CryptBlocks(scratch[:n], msg[off:off+n])
			copy(x[:], scratch[n-bs:n])
			off += n
		}
		cmacScratch.Put(scratchP)
	}

	var last [bs]byte
	copy(last[:], msg[full*bs:])
	if rem == bs {
		xor16(&last, &k1)
	} else {
		last[rem] = 0x80
		xor16(&last, &k2)
	}
	xor16(&x, &last)
	out := make([]byte, bs)
	block.Encrypt(out, x[:])
	return out
}

// gfMulX sets out to in times x in GF(2^128): a left shift with conditional reduction by the CMAC
// polynomial 0x87, which is how RFC 4493 derives the subkeys.
func gfMulX(out, in *[16]byte) {
	var carry byte
	for i := 15; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if carry != 0 {
		out[15] ^= 0x87
	}
}

func xor16(dst, src *[16]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
