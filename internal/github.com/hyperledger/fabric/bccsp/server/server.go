package server

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

// New new a server bccsp
func New(opts *Opts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration")
	}

	swCSP, err := sw.NewWithParams(opts.SecLevel, opts.HashFamily, keyStore)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing fallback SW BCCSP")
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil")
	}

	var implcsp bccsp.BCCSP
	switch opts.DefaultOpts {
	case "hbca":
		implcsp, err = newhbca(opts.HBCA)
		if err != nil {
			return nil, errors.Wrap(err, "newhbca(opts.HBCA)")
		}
	default:
		return nil, errors.Wrapf(err, "unsupport opts of server type, default:%s", opts.DefaultOpts)
	}
	csp := &impl{swCSP, conf, keyStore, implcsp}
	return csp, nil
}

func newhbca(opts *HBCAOpts) (bccsp.BCCSP, error) {
	if len(opts.AppKey) == 0 {
		panic("please set the appkey of hbca")
	}

	if len(opts.AppSecret) == 0 {
		panic("please set the appsecret of hbca")
	}

	logger.Info("Module hbca of the bccsp server loaded successfully")
	return &HuBeiCa{
		opt: opts,
	}, nil
}

// NewCert new a hbca http server
func NewCert(certServer string, opts *HBCAOpts, certAction *CertAction) HBCACert {
	return &HuBeiCa{
		opt:        opts,
		CertServer: certServer,
		CertAction: certAction,
	}
}

// HBCACert is the hbca api
type HBCACert interface {
	// CreateP10 create p10, generate the private key and public key
	CreateP10(createP10Input *CreateP10Input) (string, error)

	// CertApply app ca
	CertApply(input *HBCAApplyInput) (*ResponseCA, error)

	// ExtendCertValid cert extend
	ExtendCertValid(input *ExtendCertInput) (*ResponseCA, error)

	// CertRevoke cert revoke
	CertRevoke(input *CertRevokeInput) error

	// ImportEncCert import cert
	ImportEncCert(importEncCert *ImportEncCert) error

	// ImportSignCert import cert
	ImportSignCert(importSignCert *ImportSignCert) error

	// SignData sign data
	SignData(input []byte, certIDs ...string) ([]byte, error)

	// VerifySignedData verify sign data
	VerifySignedData(input, signBytes []byte) error

	// PubKeyEncrypt public key encrypt
	PubKeyEncrypt(input []byte, certIDs ...string) ([]byte, error)

	// PriKeyDecrypt private key decrypt
	PriKeyDecrypt(input []byte, certIDs ...string) ([]byte, error)

	// CreateP10ForUpdate create p10 for update
	CreateP10ForUpdate(certIDs ...string) (string, error)

	// ImportEncCertForUpdate import enc cert
	ImportEncCertForUpdate(importEncCert *ImportEncCert) error

	// ImportSignCertForUpdate import sign cert
	ImportSignCertForUpdate(importSignCert *ImportSignCert) error

	// GetCertInfo get cert info, if certIDs is empty, use the csp.opt.CertID, otherwise use the certIDs[0] as certID
	GetCertInfo(certIDs ...string) (*sm2.Certificate, error)
}
