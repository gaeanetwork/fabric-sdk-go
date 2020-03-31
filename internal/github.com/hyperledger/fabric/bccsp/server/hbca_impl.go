package server

import (
	"encoding/hex"
	"hash"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

// HuBeiCa a ca type
type HuBeiCa struct {
	opt        *HBCAOpts
	CertServer string
	CertAction *CertAction
}

// CertAction cert action for http server
type CertAction struct {
	CertApplyAction       string
	ExtendCertValidAction string
	CertRevokeAction      string
}

// KeyGen generates a key using opts.
func (csp *HuBeiCa) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	return nil, errors.New("not support to gen the key in the http/server model ca")
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, errors.New("not support to deriv the key in the http/server model ca")
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	pk, err := csp.GetPublickey(csp.opt.CertID)
	if err != nil {
		return nil, errors.Wrap(err, "csp.getPublickey()")
	}

	bytes, err := sm2.MarshalSm2PublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "sm2.MarshalSm2PublicKey(pk)")
	}

	k = &sm2PublicKey{pub: pk, ski: bytes}
	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *HuBeiCa) GetKey(ski []byte) (k bccsp.Key, err error) {
	certID := hex.EncodeToString(ski)
	logger.Info("GetKey[hex.EncodeToString(ski)]:", certID)

	pk, err := csp.GetPublickey(csp.opt.CertID)
	if err != nil {
		return nil, errors.Wrap(err, "csp.getPublickey()")
	}

	return &sm2PublicKey{pub: pk, ski: ski}, nil
}

// Hash hashes messages msg using options opts.
func (csp *HuBeiCa) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	digest = sm3.Sm3Sum(msg)
	return
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *HuBeiCa) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	h = sm3.New()
	return
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *HuBeiCa) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	key, err := k.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "k.PublicKey()")
	}

	// TODO: use this certID to sign
	bytes, err := key.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "key.Bytes()")
	}

	certID := hex.EncodeToString(bytes)
	logger.Info("certID for sign:", certID)
	return csp.SignData(certID, digest)
}

// Verify verifies signature against key k and digest
func (csp *HuBeiCa) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}

	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	return csp.VerifySignedData(digest, signature)
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// TODO: Add PKCS11 support for encryption, when fabric starts requiring it
	return csp.PubKeyEncrypt(plaintext)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	return csp.PriKeyDecrypt(ciphertext)
}
