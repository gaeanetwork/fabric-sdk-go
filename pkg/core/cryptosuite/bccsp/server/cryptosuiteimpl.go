package server

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	bccspServer "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory/server"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/server"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
	"github.com/pkg/errors"
)

var logger = logging.NewLogger("fabsdk.core.bccsp.server")

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	// TODO: delete this check?
	if config.SecurityProvider() != "server" {
		return nil, errors.Errorf("Unsupported BCCSP Provider: %s", config.SecurityProvider())
	}

	opts := getOptsByConfig(config)
	bccsp, err := getBCCSPFromOpts(opts)

	if err != nil {
		return nil, err
	}
	return &wrapper.CryptoSuite{BCCSP: bccsp}, nil
}

func getBCCSPFromOpts(config *server.Opts) (bccsp.BCCSP, error) {
	f := &bccspServer.Factory{}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

//getOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig(c core.CryptoSuiteConfig) *server.Opts {
	certID := c.SecurityCertID()
	opts := &server.Opts{
		SecLevel:    c.SecurityLevel(),
		HashFamily:  c.SecurityAlgorithm(),
		DefaultOpts: "hbca",
		HBCA: &server.HBCAOpts{
			HTTPServer: c.SecurityHTTPServer(),
			Protocol:   c.SecurityProtocol(),
			CertID:     int64(certID),
			AppKey:     c.SecurityAppKey(),
			AppSecret:  c.SecurityAppSecret(),
		},
	}

	logger.Info("Initialized server cryptosuite")

	return opts
}
