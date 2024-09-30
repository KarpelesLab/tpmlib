package tpmlib

import (
	"crypto"
	"crypto/ecdh"

	"github.com/KarpelesLab/cryptutil"
)

// Intf is the generic interface for TPM
type Intf interface {
	crypto.Signer
	ECDH(remote *ecdh.PublicKey) ([]byte, error) // perform ECDH operations
	ECDHPublic() (*ecdh.PublicKey, error)        // return the local public key for ECDH operations
	Keychain() *cryptutil.Keychain               // returns a keychain containing all the relevant keys
	IDCard() (*cryptutil.IDCard, error)          // return a non-signed ID Card with the keys listed in
	Read(b []byte) (int, error)                  // read random bytes using TRNG
}
