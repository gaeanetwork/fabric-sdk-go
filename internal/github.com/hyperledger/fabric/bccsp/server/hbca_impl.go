package server

import (
	"hash"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
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
	// use sw keyImport
	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *HuBeiCa) GetKey(ski []byte) (k bccsp.Key, err error) {
	// use sw GetKey
	return
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

	if len(csp.opt.CertID) > 0 {
		return csp.SignData(digest, csp.opt.CertID)
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

	certID := GenerateCertID(bytes)
	logger.Debug("certID for sign:", certID)
	return csp.SignData(digest, certID)
}

// Verify verifies signature against key k and digest
func (csp *HuBeiCa) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}

	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	if err := csp.VerifySignedData(digest, signature); err != nil {
		return false, errors.Wrap(err, "csp.VerifySignedData(digest, signature)")
	}
	return true, nil
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	if len(csp.opt.CertID) > 0 {
		return csp.PubKeyEncrypt(plaintext, csp.opt.CertID)
	}

	key, err := k.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "k.PublicKey()")
	}

	bytes, err := key.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "key.Bytes()")
	}

	certID := GenerateCertID(bytes)
	logger.Debug("certID for sign:", certID)

	return csp.PubKeyEncrypt(plaintext, certID)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	if len(csp.opt.CertID) > 0 {
		return csp.PriKeyDecrypt(ciphertext, csp.opt.CertID)
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

	certID := GenerateCertID(bytes)
	logger.Debug("certID for sign:", certID)

	return csp.PriKeyDecrypt(ciphertext, certID)
}
