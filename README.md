[![GoDoc](https://godoc.org/github.com/KarpelesLab/tpmlib?status.svg)](https://godoc.org/github.com/KarpelesLab/tpmlib)

# tpmlib

A Go library for interfacing with Trusted Platform Module (TPM) devices. This library enables applications to:

- Connect to a local TPM device
- Generate and use TPM-backed keys for cryptographic operations
- Perform signing operations using ECDSA
- Execute ECDH key exchanges
- Access TPM's hardware random number generator
- Generate attestation data
- Create cryptutil-compatible ID cards and keychains

## Installation

```bash
go get github.com/KarpelesLab/tpmlib
```

## Usage Examples

### Basic Signing Operation

```go
import (
    "crypto"
    "crypto/rand"
    "github.com/KarpelesLab/cryptutil"
    "github.com/KarpelesLab/tpmlib"
)

func signSomething(v []byte) ([]byte, error) {
    k, err := tpmlib.GetKey()
    if err != nil {
        return nil, err
    }
    return k.Sign(rand.Reader, cryptutil.Hash(v, crypto.SHA256), crypto.SHA256)
}
```

### ECDH Key Exchange

```go
import (
    "crypto/ecdh"
    "github.com/KarpelesLab/tpmlib"
)

func performECDH(remotePubKey *ecdh.PublicKey) ([]byte, error) {
    k, err := tpmlib.GetKey()
    if err != nil {
        return nil, err
    }
    
    // Get shared secret
    return k.ECDH(remotePubKey)
}
```

### Hardware Random Number Generation

```go
import "github.com/KarpelesLab/tpmlib"

func getRandomBytes(size int) ([]byte, error) {
    k, err := tpmlib.GetKey()
    if err != nil {
        return nil, err
    }
    
    // Use TPM as a source of randomness
    data := make([]byte, size)
    _, err = k.Read(data)
    if err != nil {
        return nil, err
    }
    
    return data, nil
}
```

### Working with ID Cards

```go
import "github.com/KarpelesLab/tpmlib"

func getIDCard() (*cryptutil.IDCard, error) {
    k, err := tpmlib.GetKey()
    if err != nil {
        return nil, err
    }
    
    // Generate an unsigned ID card
    return k.IDCard()
}
```

## Platform Support

- Linux: Uses `/dev/tpmrm0` then falls back to `/dev/tpm0`
- Windows: Connects to the TPM using platform-specific mechanisms

## Features

- Thread-safe TPM access with proper locking
- Singleton TPM connection to avoid resource conflicts
- Support for NIST P-256 elliptic curve cryptography
- Compatible with the KarpelesLab cryptutil ecosystem
- Self-test functionality to verify TPM operations

## Development

```bash
# Build the library
go build -v

# Run tests
go test -v

# Run a specific test
go test -v -run TestName
```

## License

See the [LICENSE](LICENSE) file for details.