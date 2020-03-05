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
	hbca := &HuBeiCa{
		HTTPServer: opts.HTTPServer,
		Protocol:   opts.Protocol,
		CertID:     opts.CertID,
		AppKey:     opts.AppKey,
		AppSecret:  opts.AppSecret,
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

	logger.Info("Module hbca of the bccsp server loaded successfully")
	return hbca, nil
}
