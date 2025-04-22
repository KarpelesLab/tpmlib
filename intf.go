package tpmlib

import (
	"crypto"
	"crypto/ecdh"

	"github.com/KarpelesLab/cryptutil"
)

// Intf is the generic interface for TPM operations.
// It extends the crypto.Signer interface with additional TPM-specific functionality
// for key exchange, random number generation, and identity management.
type Intf interface {
	// Implements crypto.Signer for signing operations using TPM-protected keys
	crypto.Signer
	
	// ECDH performs a key exchange operation with the provided remote public key.
	// It returns the shared secret or an error if ECDH operations are not available.
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
	
	// ECDHPublic returns the local public key for ECDH operations.
	// Returns an error if ECDH operations are not available.
	ECDHPublic() (*ecdh.PublicKey, error)
	
	// Keychain returns a cryptutil.Keychain containing all available TPM keys.
	// This includes both signing and encryption keys if available.
	Keychain() *cryptutil.Keychain
	
	// IDCard returns a non-signed cryptutil.IDCard with all TPM keys included.
	// The ID card can be used with the cryptutil ecosystem for secure operations.
	IDCard() (*cryptutil.IDCard, error)
	
	// Read implements io.Reader to access the TPM's True Random Number Generator.
	// It reads random bytes directly from the TPM hardware.
	Read(b []byte) (int, error)
}
