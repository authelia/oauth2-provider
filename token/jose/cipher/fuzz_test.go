package josecipher

import (
	"crypto/aes"
	"testing"
)

func FuzzCBCHMACOpen(f *testing.F) {
	f.Add(uint8(0), []byte("0123456789abcdef"), []byte(""), []byte("aad"))
	f.Add(uint8(0), []byte("0123456789abcdef"), []byte("0123456789abcdef"), []byte(""))
	f.Add(uint8(1), []byte("0123456789abcdef"), []byte("short"), []byte("aad"))
	f.Add(uint8(2), []byte("0123456789abcdef"), []byte("0123456789abcdef0123456789abcdef"), []byte("aad"))

	f.Fuzz(func(t *testing.T, keySel uint8, nonce, ciphertext, aad []byte) {
		keySize := []int{32, 48, 64}[int(keySel)%3]

		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}

		aead, err := NewCBCHMAC(key, aes.NewCipher)
		if err != nil {
			return
		}

		if len(nonce) != aead.NonceSize() {
			return
		}

		tag := aead.(*cbcAEAD).computeAuthTag(aad, nonce, ciphertext)

		_, _ = aead.Open(nil, nonce, append(append([]byte{}, ciphertext...), tag...), aad)
	})
}
