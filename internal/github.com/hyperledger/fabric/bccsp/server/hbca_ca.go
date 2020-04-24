package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fiorix/wsdl2go/soap"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/server/wsdl"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

var (
	// cacheCertBase64 cache the cert base64
	cacheCertBase64 = make(map[string]string)

	// certBase64Lock use lock when get the certbase64 of hbca
	certBase64Lock sync.Mutex

	// wsdlServer wsdl server
	wsdlServer wsdl.HbcaService

	// hbcaServerInitOnce only init once
	hbcaServerInitOnce sync.Once
)

// NewHbcaWSDL new a hbca server, first arg is Namespace, second is ContentType
func NewHbcaWSDL(WSDLServer string, args ...string) wsdl.HbcaService {
	if wsdlServer == nil {
		hbcaServerInitOnce.Do(func() {
			cli := &soap.Client{
				URL:         WSDLServer,
				Namespace:   "http://jws.back.hb.org.cn/",
				ContentType: "text/xml;charset=utf-8",
			}

			if len(args) > 0 && len(args[0]) > 0 {
				cli.Namespace = args[0]
			}

			if len(args) > 0 && len(args[1]) > 0 {
				cli.ContentType = args[1]
			}

			wsdlServer = wsdl.NewHbcaService(cli)
		})
	}
	return wsdlServer
}

// HandlerWSDLResponse handler the wsdl response
func HandlerWSDLResponse(response string) (string, error) {
	res := &ResponseWSDL{}
	if err := json.Unmarshal([]byte(response), res); err != nil {
		return "", errors.Wrap(err, "json.Unmarshal([]byte(response),res)")
	}

	if res.Code != "0" {
		return "", errors.New(fmt.Sprintf("%s:%s", res.Message, res.Data))
	}

	return res.Data, nil
}

// if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func getCertID(csp *HuBeiCa, certIDs ...string) string {
	certID := csp.opt.CertID
	if len(certIDs) > 0 && len(certIDs[0]) > 0 {
		certID = certIDs[0]
	}
	return certID
}

// GetCertBase64 get the cert base64 format, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) GetCertBase64(certIDs ...string) (string, error) {
	certID := getCertID(csp, certIDs...)
	return getCertBase64(certID, csp.opt.AppKey, csp.opt.AppSecret, csp.opt.WSDLServer)
}

func getCertBase64(certID, appKey, appSecret, WSDLServer string) (string, error) {
	certBase64Lock.Lock()
	defer certBase64Lock.Unlock()

	certStr, ok := cacheCertBase64[certID]
	if ok {
		return certStr, nil
	}

	s := NewHbcaWSDL(WSDLServer)

	certEx := &wsdl.GetServerCertEx{
		AppKey:    &appKey,
		AppSecret: &appSecret,
		CertId:    &certID,
	}

	res, err := s.GetServerCertEx(certEx)
	if err != nil {
		return "", errors.Wrap(err, "s.GetServerCertEx(certEx)")
	}

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return "", errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	cacheCertBase64[certID] = response
	return response, nil
}

// GetCertInfo get cert info, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) GetCertInfo(certIDs ...string) (*sm2.Certificate, error) {
	certID := getCertID(csp, certIDs...)

	certBase64, err := csp.GetCertBase64(certID)
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

// GetPublickey get public key, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) GetPublickey(certIDs ...string) (*sm2.PublicKey, error) {
	certID := getCertID(csp, certIDs...)

	cert, err := csp.GetCertInfo(certID)
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

// GetEncCert get enc cert, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) GetEncCert(certIDs ...string) (string, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)
	encCert := &wsdl.GetEncCert{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		CertId:    &certID,
	}

	res, err := s.GetEncCert(encCert)
	if err != nil {
		return "", errors.Wrap(err, "s.GetEncCert(encCert)")
	}

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return "", errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return response, nil
}

// GetSignCert get sign cert, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) GetSignCert(certIDs ...string) (string, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	certEx := &wsdl.GetSignCert{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		CertId:    &certID,
	}

	res, err := s.GetSignCert(certEx)
	if err != nil {
		return "", errors.Wrap(err, "s.GetSignCert(certEx)")
	}

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return "", errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return response, nil
}

// SignData sign data, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) SignData(input []byte, certIDs ...string) ([]byte, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)
	oriData := base64.StdEncoding.EncodeToString(input)
	data := &wsdl.SignDataEx{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		CertId:    &certID,
		OriData:   &oriData,
	}

	res, err := s.SignDataEx(data)
	if err != nil {
		return nil, errors.Wrap(err, "s.SignDataEx(data)")
	}

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return nil, errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	output, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(response)")
	}

	sd := &hbcaSignData{
		SignData: output,
		CertID:   certID,
	}

	bytes, err := json.Marshal(sd)
	if err != nil {
		return nil, errors.Wrap(err, "json.Marshal(sd)")
	}

	return bytes, nil
}

// VerifySignedData verify sign data
func (csp *HuBeiCa) VerifySignedData(input, signBytes []byte) error {
	sd := &hbcaSignData{}
	if err := json.Unmarshal(signBytes, sd); err != nil {
		return errors.Wrap(err, "json.Unmarshal(signBytes,sd)")
	}

	certBase64, err := csp.GetSignCert(sd.CertID)
	if err != nil {
		return errors.Wrap(err, "csp.getCertBase64()")
	}

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	inData := base64.StdEncoding.EncodeToString(input)
	signData := base64.StdEncoding.EncodeToString(sd.SignData)
	data := &wsdl.VerifySignedDataP1{
		AppKey:     &csp.opt.AppKey,
		AppSecret:  &csp.opt.AppSecret,
		InData:     &inData,
		SignedData: &signData,
		BstrCert:   &certBase64,
	}

	res, err := s.VerifySignedDataP1(data)
	if err != nil {
		return errors.Wrap(err, "s.VerifySignedDataP1(data)")
	}

	if _, err = HandlerWSDLResponse(*res.Return); err != nil {
		return errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return nil
}

// PubKeyEncrypt public key encrypt, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) PubKeyEncrypt(input []byte, certIDs ...string) ([]byte, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	inData := base64.StdEncoding.EncodeToString(input)
	data := &wsdl.PubKeyEncryptEx{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		EncCertId: &certID,
		InData:    &inData,
	}

	res, err := s.PubKeyEncryptEx(data)
	if err != nil {
		return nil, errors.Wrap(err, "s.PubKeyEncryptEx(data)")
	}

	logger.Debugf("pub key encrypt, certID:%s, response:%s", certID, *res.Return)

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return nil, errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	output, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(response)")
	}
	return output, nil
}

// PriKeyDecrypt private key decrypt, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
func (csp *HuBeiCa) PriKeyDecrypt(input []byte, certIDs ...string) ([]byte, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	strInput := base64.StdEncoding.EncodeToString(input)
	data := &wsdl.PriKeyDecryptEx{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		EncCertId: &certID,
		InData:    &strInput,
	}

	res, err := s.PriKeyDecryptEx(data)
	if err != nil {
		return nil, errors.Wrap(err, "s.PriKeyDecryptEx(data)")
	}

	logger.Debugf("prikey decrypt, certID:%s, response:%s", certID, *res.Return)

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return nil, errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	output, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}

	output, err = base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}

	return output, nil
}

// CreateP10 create p10
func (csp *HuBeiCa) CreateP10(createP10Input *CreateP10Input) (string, error) {
	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.CreateP10{
		AppKey:     &csp.opt.AppKey,
		AppSecret:  &csp.opt.AppSecret,
		CertId:     &createP10Input.CertID,
		CertName:   &createP10Input.CertName,
		ApplyDn:    &createP10Input.ApplyDn,
		EncryptAlg: &createP10Input.EncryptAlg,
		KeyLength:  &createP10Input.KeyLength,
		DigestAlg:  &createP10Input.DigestAlg,
	}

	res, err := s.CreateP10(data)
	if err != nil {
		return "", errors.Wrap(err, "s.CreateP10(data)")
	}

	logger.Debugf("create p10, certID:%s, response:%s", createP10Input.CertID, *res.Return)

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return "", errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return response, nil
}

// ImportEncCert import enc cert
func (csp *HuBeiCa) ImportEncCert(importEncCert *ImportEncCert) error {
	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.ImportEncCert{
		AppKey:          &csp.opt.AppKey,
		AppSecret:       &csp.opt.AppSecret,
		RootId:          &importEncCert.RootID,
		SignCertId:      &importEncCert.SignCertID,
		EncCertId:       &importEncCert.EncCertID,
		EncCertB64:      &importEncCert.EncCertB64,
		DoubleEncPriKey: &importEncCert.DoubleEncPriKey,
		CertType:        &importEncCert.CertType,
	}

	res, err := s.ImportEncCert(data)
	if err != nil {
		return errors.Wrap(err, "s.ImportEncCert(data)")
	}

	logger.Debugf("import encert response, certID:%s, response:%s", importEncCert.EncCertID, *res.Return)

	if _, err = HandlerWSDLResponse(*res.Return); err != nil {
		return errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return nil
}

// ImportSignCert import sign cert
func (csp *HuBeiCa) ImportSignCert(importSignCert *ImportSignCert) error {
	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.ImportSignCert{
		AppKey:       &csp.opt.AppKey,
		AppSecret:    &csp.opt.AppSecret,
		CertId:       &importSignCert.CertID,
		CertName:     &importSignCert.CertName,
		SignCertB64:  &importSignCert.SignCertB64,
		CertType:     &importSignCert.CertType,
		RootCertName: &importSignCert.RootCertName,
		ImportType:   &importSignCert.ImportType,
		Password:     &importSignCert.Password,
	}

	res, err := s.ImportSignCert(data)
	if err != nil {
		return errors.Wrap(err, "s.ImportSignCert(data)")
	}

	logger.Debugf("import sign cert response, certID:%s, response:%s", importSignCert.CertID, *res.Return)

	if _, err = HandlerWSDLResponse(*res.Return); err != nil {
		return errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return nil
}

// CreateP10ForUpdate create p10
func (csp *HuBeiCa) CreateP10ForUpdate(certIDs ...string) (string, error) {
	certID := getCertID(csp, certIDs...)

	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.CreateP10ForUpdate{
		AppKey:    &csp.opt.AppKey,
		AppSecret: &csp.opt.AppSecret,
		CertId:    &certID,
	}

	res, err := s.CreateP10ForUpdate(data)
	if err != nil {
		return "", errors.Wrap(err, "s.ImportSignCert(data)")
	}

	logger.Debugf("create p10 for update, certID:%s, response:%s", certID, *res.Return)

	response, err := HandlerWSDLResponse(*res.Return)
	if err != nil {
		return "", errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return response, nil
}

// ImportEncCertForUpdate import enc cert
func (csp *HuBeiCa) ImportEncCertForUpdate(importEncCert *ImportEncCert) error {
	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.ImportEncCertForUpdate{
		AppKey:          &csp.opt.AppKey,
		AppSecret:       &csp.opt.AppSecret,
		RootId:          &importEncCert.RootID,
		SignCertId:      &importEncCert.SignCertID,
		EncCertId:       &importEncCert.EncCertID,
		EncCertB64:      &importEncCert.EncCertB64,
		DoubleEncPriKey: &importEncCert.DoubleEncPriKey,
		CertType:        &importEncCert.CertType,
	}

	res, err := s.ImportEncCertForUpdate(data)
	if err != nil {
		return errors.Wrap(err, "s.ImportEncCert(data)")
	}

	logger.Debugf("import encert for update response, certID:%s, response:%s", importEncCert.EncCertID, *res.Return)

	if _, err = HandlerWSDLResponse(*res.Return); err != nil {
		return errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return nil
}

// ImportSignCertForUpdate import sign cert
func (csp *HuBeiCa) ImportSignCertForUpdate(importSignCert *ImportSignCert) error {
	s := NewHbcaWSDL(csp.opt.WSDLServer, csp.opt.Namespace, csp.opt.ContentType)

	data := &wsdl.ImportSignCertForUpdate{
		AppKey:       &csp.opt.AppKey,
		AppSecret:    &csp.opt.AppSecret,
		CertId:       &importSignCert.CertID,
		CertName:     &importSignCert.CertName,
		SignCertB64:  &importSignCert.SignCertB64,
		CertType:     &importSignCert.CertType,
		RootCertName: &importSignCert.RootCertName,
		ImportType:   &importSignCert.ImportType,
		Password:     &importSignCert.Password,
	}

	res, err := s.ImportSignCertForUpdate(data)
	if err != nil {
		return errors.Wrap(err, "s.ImportSignCert(data)")
	}

	logger.Debugf("import sign cert for update response, certID:%s, response:%s", importSignCert.CertID, *res.Return)

	if _, err = HandlerWSDLResponse(*res.Return); err != nil {
		return errors.Wrap(err, "HandlerWSDLResponse(*res.Return)")
	}

	return nil
}

// CertApply cert apply
func (csp *HuBeiCa) CertApply(input *HBCAApplyInput) (*ResponseCA, error) {
	url := fmt.Sprintf("%s%s", csp.CertServer, csp.CertAction.CertApplyAction)
	return httpRequestJSON("POST", url, input)
}

// ExtendCertValid cert extend
func (csp *HuBeiCa) ExtendCertValid(input *ExtendCertInput) (*ResponseCA, error) {
	url := fmt.Sprintf("%s%s", csp.CertServer, csp.CertAction.ExtendCertValidAction)
	return httpRequestJSON("POST", url, input)
}

// CertRevoke cert revoke
func (csp *HuBeiCa) CertRevoke(input *CertRevokeInput) error {
	url := fmt.Sprintf("%s%s", csp.CertServer, csp.CertAction.CertRevokeAction)
	_, err := httpRequestJSON("POST", url, input)
	if err != nil {
		return errors.Wrap(err, "httpRequestJSON(\"POST\", url, input)")
	}
	return nil
}
