// Package tpmlib provides TPM device connectivity and operations.
package tpmlib

import (
	"io"
	"sync"
)

var (
	tpmConn   io.ReadWriteCloser
	tpmConnLk sync.Mutex
)

// OpenTPM connects to the local TPM device.
//
// This function provides access to the TPM device using platform-specific mechanisms.
// On Linux, it attempts to connect to /dev/tpmrm0 first, then falls back to /dev/tpm0.
// On Windows, it uses platform-specific mechanisms to access the TPM.
//
// OpenTPM implements a singleton pattern - multiple calls will always return the
// same connection object. This prevents resource conflicts when accessing the TPM.
// The function is thread-safe through the use of a mutex lock.
//
// It returns an io.ReadWriteCloser interface for communicating with the TPM device.
// If connection to the TPM fails, an error is returned.
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
