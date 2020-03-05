package server

import (
	"bytes"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
)

func testImp() (*HuBeiCa, error) {
	hbca := &HuBeiCa{
		Protocol:   "http",
		HTTPServer: "221.232.224.75:8082",
		CertID:     109,
		AppKey:     "TESTAPPKEY",
		AppSecret:  "TESTAPPSECRECT",
	}

	var err error
	hbca.certBase64, err = hbca.getCertBase64()
	if err != nil {
		return nil, errors.Wrap(err, "hbca.getCertBase64()")
	}

	hbca.validate, err = hbca.validateCert()
	if err != nil {
		return nil, errors.Wrap(err, "hbca.getCertBase64()")
	}

	hbca.cert, err = hbca.getCertInfo()
	if err != nil {
		return nil, errors.Wrap(err, "hbca.getCertInfo()")
	}

	hbca.pk, err = hbca.getPublickey()
	if err != nil {
		return nil, errors.Wrap(err, "hbca.getPublickey()")
	}
	return hbca, nil
}

func testErrorImp() *HuBeiCa {
	return &HuBeiCa{
		Protocol:   "http",
		HTTPServer: "221.232.224.75:8082",
		CertID:     10259,
		AppKey:     "TESTAPPKEY",
		AppSecret:  "TESTAPPSECRECT",
	}
}

func Test_CA_GetCertBase64(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	certBase64, err := implTest.getCertBase64()
	assert.Nil(t, err)
	assert.NotEmpty(t, certBase64)

	impError := testErrorImp()
	ErrorPublicKeyBytes, err := impError.getCertBase64()
	assert.Error(t, err)
	assert.Empty(t, ErrorPublicKeyBytes)
}

func Test_CA_GetCertInfo(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	cert, err := implTest.getCertInfo()
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	bytes, err := sm2.MarshalPKIXPublicKey(cert.PublicKey)
	assert.Nil(t, err)

	pk, err := sm2.ParseSm2PublicKey(bytes)
	assert.Nil(t, err)
	assert.NotNil(t, pk)

	impError := testErrorImp()
	errorCert, err := impError.getCertInfo()
	assert.Error(t, err)
	assert.Nil(t, errorCert)
}

func Test_CA_ValidateCert(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	ok, err := implTest.validateCert()
	assert.Nil(t, err)
	assert.True(t, ok)

	impError := testErrorImp()
	ok, err = impError.validateCert()
	assert.Error(t, err)
	assert.False(t, ok)
}

func Test_CA_SignAndVerifyData(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	inData := []byte("123456")
	outputBytes, err := implTest.signData(inData)
	assert.Nil(t, err)
	assert.NotNil(t, outputBytes)

	ok, err := implTest.verifySignedData(inData, outputBytes)
	assert.Nil(t, err)
	assert.True(t, ok)

	errInData := []byte("1234567")
	ok, err = implTest.verifySignedData(errInData, outputBytes)
	assert.NotNil(t, err)
	assert.False(t, ok)

	errSingData := []byte("1234567")
	ok, err = implTest.verifySignedData(inData, errSingData)
	assert.NotNil(t, err)
	assert.False(t, ok)
}

func Test_CA_pubKeyEncryptAndPriKeyDecrypt(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	inData := []byte("123456")
	ciphertext, err := implTest.pubKeyEncrypt(inData)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	plaintext, err := implTest.priKeyDecrypt(ciphertext)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(inData, plaintext))

	errInData := []byte("1234567")
	plaintext, err = implTest.priKeyDecrypt(errInData)
	assert.NotNil(t, err)
	assert.False(t, bytes.Equal(inData, plaintext))
}
