package server

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
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
func NewCert(certServer string, certAction *CertAction) HBCACert {
	return &HuBeiCa{
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
}
