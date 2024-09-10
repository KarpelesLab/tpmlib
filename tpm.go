package tpmlib

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpmKey struct {
	lk      sync.Mutex
	key     *client.Key
	ecdhkey *client.Key
	tpmConn io.ReadWriteCloser
}

var (
	tpmKeyObject *tpmKey
	tpmKeyInit   sync.Mutex

	tpmKeyTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgNull, KeyBits: 0, Mode: 0},
			Sign:      &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID:   tpm2.CurveNISTP256,
		},
	}
	tpmECDHKeyTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Point:   tpm2.ECPoint{},
		},
	}
)

// This struct is used to marshal and unmarshal an ECDSA signature,
// which consists of two big integers.
type ecdsaSignature struct {
	R, S *big.Int
}

// GetKey returns an object that corresponds to the local machine's TPM. Multiple calls of GetKey will return the same object.
func GetKey() (Intf, error) {
	tpmKeyInit.Lock()
	defer tpmKeyInit.Unlock()

	if tpmKeyObject != nil {
		return tpmKeyObject, nil
	}

	// the default paths on Linux (/dev/tpmrm0 then /dev/tpm0), will be used
	tpmConn, err := OpenTPM()
	if err != nil {
		return nil, err
	}

	// only perform this after we got a successful connection to the tpm
	handle := tpmutil.Handle(0x81010001)
	var key *client.Key
	key, err = client.NewCachedKey(tpmConn, tpm2.HandleOwner, tpmKeyTemplate, handle)
	if err != nil {
		return nil, err
	}

	tpmKeyObject = &tpmKey{
		key:     key,
		tpmConn: tpmConn,
	}

	// attempt to make a ECDH key too
	ecdhhandle := tpmutil.Handle(0x81010002)
	tpmKeyObject.ecdhkey, err = client.NewCachedKey(tpmConn, tpm2.HandleOwner, tpmECDHKeyTemplate, ecdhhandle)
	if err != nil {
		slog.Info(fmt.Sprintf("failed to get key for ECDH: %s", err), "event", "tpm:fail_ecdh")
		tpmKeyObject.ecdhkey = nil
	}

	//slog.Info(fmt.Sprintf("instanciated tpm key: %s", tpmKeyObject.String()), "event", "fleet:tpm:init")

	return tpmKeyObject, nil
}

func (k *tpmKey) Public() crypto.PublicKey {
	return k.key.PublicKey()
}

func (k *tpmKey) String() string {
	b, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return fmt.Sprintf("INVALID KEY (%s)", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// IDCard returns an unsigned IDCard
func (k *tpmKey) IDCard() (*cryptutil.IDCard, error) {
	id, err := cryptutil.NewIDCard(tpmKeyObject.Public())
	if err != nil {
		return nil, err
	}
	id.AddKeychain(k.Keychain())
	return id, nil
}

// ECDH returns the ECDH value generated from the locally stored private key and the passed
// ephemeral key
func (k *tpmKey) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	if tpmKeyObject.ecdhkey == nil {
		return nil, errors.New("ECDH operations are not available")
	}
	b := remote.Bytes()[1:]
	l := len(b) / 2
	ephemeralPub := tpm2.ECPoint{
		XRaw: b[:l],
		YRaw: b[l:],
	}

	z, err := tpm2.ECDHZGen(k.tpmConn, tpmKeyObject.ecdhkey.Handle(), "", ephemeralPub)
	if err != nil {
		return nil, err
	}
	return z.X().Bytes(), nil
}

// ECDHPublic returns the key's public key
func (k *tpmKey) ECDHPublic() (*ecdh.PublicKey, error) {
	if k.ecdhkey == nil {
		return nil, errors.New("ECDH operations not available")
	}
	switch v := tpmKeyObject.ecdhkey.PublicKey().(type) {
	case *ecdsa.PublicKey:
		return v.ECDH()
	case *ecdh.PublicKey:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", v)
	}
}

// Keychain returns a [cryptutil.Keychain] containing both signing and encryption keys for the current TPM
func (k *tpmKey) Keychain() *cryptutil.Keychain {
	kc := cryptutil.NewKeychain()
	kc.AddKey(&tpmSignKey{k})
	if k.ecdhkey != nil {
		kc.AddKey(&tpmCryptKey{k})
	}
	return kc
}

// Test performs some tests on the tpm, making sure everything works as expected
func (k *tpmKey) Test() error {
	id, err := k.IDCard()
	if err != nil {
		return err
	}
	kc := k.Keychain()

	testBytes := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, testBytes)
	if err != nil {
		return err
	}

	// generate encrypted/signed bottle
	bot := cryptutil.NewBottle(testBytes)
	// encrypt
	err = bot.Encrypt(rand.Reader, id)
	if err != nil {
		return err
	}
	// sign
	bot.BottleUp()
	err = bot.Sign(rand.Reader, kc.FirstSigner(), crypto.SHA256)
	if err != nil {
		return err
	}

	// decrypt/open bottle
	op, err := cryptutil.NewOpener(kc)
	if err != nil {
		return err
	}
	res, info, err := op.Open(bot)
	if err != nil {
		return fmt.Errorf("failed to open bottle: %w", err)
	}
	if info.Decryption != 1 {
		return errors.New("excepted decryption missing")
	}
	if !bytes.Equal(res, testBytes) {
		return errors.New("result bytes are not matching original bytes")
	}
	if !info.SignedBy(id) {
		return errors.New("could not confirm signature")
	}

	return nil
}

func (k *tpmKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	halg, err := tpm2.HashToAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	k.lk.Lock()
	defer k.lk.Unlock()

	// rand will be ignored because the tpm will do the signature
	sig, err := tpm2.Sign(k.tpmConn, k.key.Handle(), "", digest, nil, &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: halg})
	if err != nil {
		return nil, err
	}

	// prepare a structure that can be marshalled by asn1
	ecdsaSig := ecdsaSignature{
		R: sig.ECC.R,
		S: sig.ECC.S,
	}
	return asn1.Marshal(ecdsaSig)
}

func (k *tpmKey) Attest() ([]byte, error) {
	// attempt to generate attestation
	t := time.Now()
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], uint64(t.Unix()))
	binary.BigEndian.PutUint32(buf[8:], uint32(t.Nanosecond()))

	// grab public key
	pubK := k.Public()
	if pubK == nil {
		return nil, errors.New("no public key")
	}
	pubB, err := x509.MarshalPKIXPublicKey(pubK)
	if err != nil {
		return nil, fmt.Errorf("while marshaling public key: %w", err)
	}

	nonce := buf // append(buf, pubB...)
	_ = pubB

	slog.Debug(fmt.Sprintf("preparing to attest nonce=%x", nonce), "event", "fleet:tpm:prep")

	// prepare attestation
	key, err := client.GceAttestationKeyECC(k.tpmConn)
	if err != nil {
		slog.Warn(fmt.Sprintf("[tpm] failed loading gce key, attempting standard attestation key..."), "event", "fleet:tpm:gce_fail")
		key, err = client.AttestationKeyECC(k.tpmConn)
	}
	if err != nil {
		slog.Error(fmt.Sprintf("[tpm] attestation key not available: %s", err), "event", "fleet:tpm:attest_fail")
		return nil, fmt.Errorf("failed loading attestation key: %w", err)
	}
	res, err := key.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %w", err)
	}

	return json.Marshal(res)
}
