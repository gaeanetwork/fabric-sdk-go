package bccsp

import "io"

// SM2KeyGenOpts contains options for sm2 key generation.
type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM3Opts contains options for SM3.
type SM3Opts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM3Opts) Ephemeral() bool {
	return opts.Temporary
}

// SM4Opts contains options for SM4.
type SM4Opts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4Opts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4Opts) Ephemeral() bool {
	return opts.Temporary
}

// SM4CBCPKCS7ModeOpts contains options for sm4 encryption in CBC mode
// with PKCS7 padding.
// Notice that both IV and PRNG can be nil. In that case, the BCCSP implementation
// is supposed to sample the IV using a cryptographic secure PRNG.
// Notice also that either IV or PRNG can be different from nil.
type SM4CBCPKCS7ModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Sm2PublicKeyImportOpts contains options for importing public keys from an x509 certificate
type Sm2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *Sm2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *Sm2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
