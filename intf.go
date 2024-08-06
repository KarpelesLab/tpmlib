package tpmlib

import (
	"crypto"
	"crypto/ecdh"

	"github.com/KarpelesLab/cryptutil"
)

// Intf is the generic interface for TPM
type Intf interface {
	crypto.Signer
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
	ECDHPublic() crypto.PublicKey
	IDCard() (*cryptutil.IDCard, error)
	Attest() ([]byte, error)
}
