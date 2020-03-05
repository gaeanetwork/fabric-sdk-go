package server

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

type sm2PrivateKey struct {
	ski []byte
	pub sm2PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() []byte {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &k.pub, nil
}

type sm2PublicKey struct {
	ski []byte
	pub *sm2.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = sm2.MarshalSm2PublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *sm2PublicKey) SKI() []byte {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

// GetSm2PublickeyByCert get the public key by certificate
func GetSm2PublickeyByCert(cert *sm2.Certificate) (*sm2.PublicKey, error) {
	bytes, err := sm2.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "sm2.MarshalPKIXPublicKey(cert.PublicKey)")
	}

	pk, err := sm2.ParseSm2PublicKey(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "sm2.ParseSm2PublicKey(bytes)")
	}
	return pk, nil
}
