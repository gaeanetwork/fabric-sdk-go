package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

var (
	cacheCertBase64 = make(map[string]string)

	getCertBase64Lock sync.Mutex
)

type hbcaSignData struct {
	SignData  []byte
	CertID    int64
	DigestAlg string
}

func (csp *HuBeiCa) getCertBase64() (string, error) {
	return getCertBase64(fmt.Sprint(csp.CertID), csp.AppKey, csp.AppSecret, csp.Protocol, csp.HTTPServer)
}

func getCertBase64(certID, appKey, appSecret, protocol, HTTPServer string) (string, error) {
	getCertBase64Lock.Lock()
	defer getCertBase64Lock.Unlock()

	certStr, ok := cacheCertBase64[certID]
	if ok {
		return certStr, nil
	}

	mapData := make(map[string]interface{})
	mapData["id"] = certID
	mapData["appKey"] = appKey
	mapData["appSecret"] = appSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetSignCertById.do", protocol, HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	cacheCertBase64[certID] = res.Message

	return res.Message, nil
}

func (csp *HuBeiCa) getCertInfo() (*sm2.Certificate, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return nil, errors.Wrap(err, "csp.getCertBase64()")
	}

	bytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}

	cert, err := sm2.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "sm2.ParseCertificate(publicKeyBytes)")
	}
	return cert, nil
}

func (csp *HuBeiCa) getPublickey() (*sm2.PublicKey, error) {
	cert, err := csp.getCertInfo()
	if err != nil {
		return nil, errors.Wrap(err, "sm2.ParseCertificate(publicKeyBytes)")
	}

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

func (csp *HuBeiCa) getCertTheme() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 1
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) getCertSerialNumber() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 2
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) getCertIssuerSubject() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 3
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) getCertEntity() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 14
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) validateCert() (bool, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return false, errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/ValidateCert.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return false, errors.Wrap(err, "failed to request public")
	}

	if res.Message == "有效的证书!" {
		return true, nil
	}

	return false, errors.New(res.Message)
}

func (csp *HuBeiCa) signData(input []byte) ([]byte, error) {
	if !csp.validate {
		return nil, errors.New("ca is invalidate")
	}

	mapData := make(map[string]interface{})
	mapData["signedCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)
	mapData["digestAlg"] = "SM3WITHSM2"

	url := fmt.Sprintf("%s://%s/hbcaDSS/SignData.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}

	sd := &hbcaSignData{
		SignData:  output,
		CertID:    csp.CertID,
		DigestAlg: "SM3WITHSM2",
	}

	bytes, err := json.Marshal(sd)
	if err != nil {
		return nil, errors.Wrap(err, "json.Marshal(sd)")
	}

	logger.Info("hbca invoke singData method,",
		"input:", base64.StdEncoding.EncodeToString(input),
		"signData:", res.Message,
		"output:", base64.StdEncoding.EncodeToString(bytes))
	return bytes, nil
}

func (csp *HuBeiCa) verifySignedData(input, signBytes []byte) (bool, error) {
	if !csp.validate {
		return false, errors.New("ca is invalidate")
	}

	sd := &hbcaSignData{}
	if err := json.Unmarshal(signBytes, sd); err != nil {
		return false, errors.Wrap(err, "json.Unmarshal(signBytes,sd)")
	}

	logger.Info("hbca invoke verifySignedData method,",
		"input:", base64.StdEncoding.EncodeToString(input),
		"signData:", base64.StdEncoding.EncodeToString(sd.SignData),
		"output:", base64.StdEncoding.EncodeToString(signBytes))

	certStr, err := getCertBase64(fmt.Sprint(sd.CertID), csp.AppKey, csp.AppSecret, csp.Protocol, csp.HTTPServer)
	if err != nil {
		return false, errors.Wrap(err, "getCertBase64(fmt.Sprint(sd.CertID),csp.AppKey,csp.AppSecret)")
	}

	mapData := make(map[string]interface{})
	mapData["signedCertAlias"] = fmt.Sprint(sd.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)
	mapData["digestAlg"] = sd.DigestAlg
	mapData["signData"] = base64.StdEncoding.EncodeToString(sd.SignData)
	mapData["certB64"] = certStr

	url := fmt.Sprintf("%s://%s/hbcaDSS/VerifySignedData.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return false, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return false, errors.New(fmt.Sprintf("input:%s, sign:%s, err:%s", base64.StdEncoding.EncodeToString(input), base64.StdEncoding.EncodeToString(signBytes), res.Code))
	}

	return true, nil
}

func (csp *HuBeiCa) pubKeyEncrypt(input []byte) ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["encryptCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)

	url := fmt.Sprintf("%s://%s/hbcaDSS/PubKeyEncrypt.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}
	return output, nil
}

func (csp *HuBeiCa) priKeyDecrypt(input []byte) ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["decryptCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)

	url := fmt.Sprintf("%s://%s/hbcaDSS/PriKeyDecrypt.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}
	return output, nil
}
