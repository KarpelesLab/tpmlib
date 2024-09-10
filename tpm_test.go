package tpmlib

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
)

var tplCAcrt = x509.Certificate{
	BasicConstraintsValid: true,
	IsCA:                  true,
	SerialNumber:          big.NewInt(1),
	Issuer:                pkix.Name{CommonName: "Local Fleet CA"},
	Subject:               pkix.Name{CommonName: "Local Fleet CA"},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	MaxPathLen:            1,
}

func TestTpm(t *testing.T) {
	// initialize tpm simulator
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Fatalf("could not initialize TPM simulator: %s", err)
		return
	}

	mfg, err := tpm2.GetManufacturer(sim)
	if err == nil {
		log.Printf("TPM manufacturer: %s", mfg)
	} else {
		log.Printf("Failed to get manufacturer: %s", err)
	}

	// setting tpmConn here ensures the simulator is used for tests
	tpmConn = sim

	ktest, err := GetKey()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
		return
	}

	err = ktest.(interface{ Test() error }).Test()
	if err != nil {
		t.Errorf("tpm self test failed: %s", err)
	}

	// get public key
	pubKey := ktest.Public()
	if pubKey == nil {
		t.Fatalf("could not get public key")
		return
	}

	pubBin, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("could not marshal public key: %s", err)
		return
	}
	log.Printf("public key = %s", base64.RawURLEncoding.EncodeToString(pubBin))

	// attempt to generate a x509 certificate
	tplCA := tplCAcrt
	tplCA.NotBefore = time.Now()
	tplCA.NotAfter = tplCA.NotBefore.Add(10 * 365 * 24 * time.Hour) // +10 years (more or less)

	ca_crt_der, err := x509.CreateCertificate(rand.Reader, &tplCA, &tplCA, pubKey, ktest)
	if err != nil {
		t.Fatalf("could not sign certificate: %s", err)
		return
	}

	ca_crt, err := x509.ParseCertificate(ca_crt_der)
	if err != nil {
		t.Fatalf("could not parse certificate: %s", err)
		return
	}
	ca_crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca_crt_der})

	if !reflect.DeepEqual(ca_crt.PublicKey, pubKey) {
		t.Errorf("public key is different")
	}

	log.Printf("generated CA:\n%s", ca_crt_pem)

	err = ca_crt.CheckSignatureFrom(ca_crt)
	if err != nil {
		t.Errorf("failed to check signature: %s", err)
	}

	// test attest
	attest, err := ktest.(interface{ Attest() ([]byte, error) }).Attest()
	if err != nil {
		t.Errorf("attest failed = %s", err)
	} else {
		log.Printf("attest = %s", attest)
	}
}
