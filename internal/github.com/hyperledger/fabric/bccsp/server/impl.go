package server

import (
	"hash"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	"github.com/pkg/errors"
)

var (
	logger = flogging.MustGetLogger("fabric.sdk.go.bccsp.server")
)

type impl struct {
	bccsp.BCCSP

	conf *config
	ks   bccsp.KeyStore

	implcsp bccsp.BCCSP
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	switch opts.(type) {
	case *bccsp.SM2KeyGenOpts:
		return nil, errors.New("not support to gen the key in the http/server model ca")
	default:
		return csp.BCCSP.KeyGen(opts)
	}
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	k, err = csp.BCCSP.KeyImport(raw, opts)
	if err != nil {
		err = errors.Wrap(err, "csp.BCCSP.KeyImport(raw, opts)")
		return
	}

	if err = csp.ks.StoreKey(k); err != nil {
		// TODO errors.As
		if strings.Contains(err.Error(), "already exists in the keystore") {
			err = nil
			return
		}
		err = errors.Wrap(err, "csp.ks.StoreKey(k)")
	}
	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *impl) GetKey(ski []byte) (bccsp.Key, error) {
	return csp.ks.GetKey(ski)
}

// Hash hashes messages msg using options opts.
func (csp *impl) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	return csp.implcsp.Hash(msg, opts)
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return csp.implcsp.GetHash(opts)
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}

	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	return csp.implcsp.Sign(k, digest, opts)
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	return csp.implcsp.Verify(k, signature, digest, opts)
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// TODO: Add PKCS11 support for encryption, when fabric starts requiring it
	// return csp.pubKeyEncrypt(plaintext)
	return csp.BCCSP.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// return csp.priKeyDecrypt(ciphertext)
	return csp.BCCSP.Decrypt(k, ciphertext, opts)
}
