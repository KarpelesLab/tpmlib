[![GoDoc](https://godoc.org/github.com/KarpelesLab/tpmlib?status.svg)](https://godoc.org/github.com/KarpelesLab/tpmlib)

# tpmlib

Simple library to connect to local tpm, generate a local key and use it as a signer.

## Usage

```go
import "github.com/KarpelesLab/tpmlib"

func signSomething(v []byte) ([]byte, error) {
    k, err := tpmlib.GetKey()
    if err != nil {
        return nil, err
    }
    return k.Sign(rand.Reader, cryptutil.Hash(v, crypto.SHA256), crypto.SHA256)
}
```
