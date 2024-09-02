package tpmlib

import (
	"crypto"
	"crypto/ecdh"
	"io"

	"github.com/KarpelesLab/cryptutil"
)

type tpmSignKey struct {
	parent *tpmKey
}

type tpmCryptKey struct {
	parent *tpmKey
}

func (t *tpmSignKey) Public() crypto.PublicKey {
	return t.parent.key.PublicKey()
}

func (t *tpmSignKey) Equal(x crypto.PrivateKey) bool {
	if xp := cryptutil.PublicKey(x); xp != nil {
		return xp.Equal(t.Public())
	}
	return false
}

func (t *tpmSignKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.parent.Sign(rand, digest, opts)
}

func (t *tpmSignKey) KeyPurposes() []string {
	return []string{"tpm-sign", "sign"}
}

func (t *tpmCryptKey) Public() crypto.PublicKey {
	return t.PublicKey()
}

func (t *tpmCryptKey) PublicKey() *ecdh.PublicKey {
	if pub, err := t.parent.ECDHPublic(); err == nil {
		return pub
	}
	return nil
}

func (t *tpmCryptKey) Equal(x crypto.PrivateKey) bool {
	if xp := cryptutil.PublicKey(x); xp != nil {
		return xp.Equal(t.Public())
	}
	return false
}

func (t *tpmCryptKey) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	return t.parent.ECDH(remote)
}

func (t *tpmCryptKey) KeyPurposes() []string {
	return []string{"tpm-decrypt", "decrypt"}
}
