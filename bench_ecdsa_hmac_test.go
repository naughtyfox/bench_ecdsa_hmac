package bench_ecdsa_hmac

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func BenchmarkHMacSha256(b *testing.B) {
	keys := make([][32]byte, b.N)
	messages := make([][256]byte, b.N)

	for i := 0; i <  b.N; i++ {
		key := [32]byte{}
		if _, err := rand.Read(key[:]); err != nil {
			b.Fatalf("Failed to generate random key: %s", err)
		}

		msg := [256]byte{}
		if _, err := rand.Read(msg[:]); err != nil {
			b.Fatalf("Failed to generate random key: %s", err)
		}

		keys[i] = key
		messages[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac := hmac.New(sha256.New, keys[i][:])
		mac.Write(messages[i][:])
		mac.Sum(nil)
	}
}

func BenchmarkEcdsaP256(b *testing.B) {
	keys := make([]*ecdsa.PrivateKey, b.N)
	messages := make([][256]byte, b.N)

	for i := 0; i <  b.N; i++ {
		bytes := [32]byte{}
		if _, err := rand.Read(bytes[:]); err != nil {
			b.Fatalf("Failed to generate random key: %s", err)
		}

		key := bytesToEcdsaPrivateKey(bytes[:])

		msg := [256]byte{}
		if _, err := rand.Read(msg[:]); err != nil {
			b.Fatalf("Failed to generate random key: %s", err)
		}

		keys[i] = key
		messages[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(messages[i][:])
		_, _, err := ecdsa.Sign(rand.Reader, keys[i], h.Sum(nil))
		if err != nil {
			b.Fatalf("Failed to generate ECDSA: %s", err)
		}
	}
}

func bytesToEcdsaPrivateKey(priv []byte) *ecdsa.PrivateKey {
	intK := big.NewInt(0).SetBytes(priv)
	x, y := elliptic.P256().ScalarBaseMult(priv)

	sk := &ecdsa.PrivateKey{
		D: intK,
		PublicKey: ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: elliptic.P256(),
		},
	}

	return sk
}