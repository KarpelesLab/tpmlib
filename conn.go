package tpmlib

import (
	"io"
	"sync"
)

var (
	tpmConn   io.ReadWriteCloser
	tpmConnLk sync.Mutex
)

// OpenTPM connects to the local TPM. Mutliple calls will always return the same connection.
func OpenTPM() (io.ReadWriteCloser, error) {
	tpmConnLk.Lock()
	defer tpmConnLk.Unlock()

	if tpmConn == nil {
		var err error
		tpmConn, err = tpm2open()
		if err != nil {
			return nil, err
		}
	}

	return tpmConn, nil
}
