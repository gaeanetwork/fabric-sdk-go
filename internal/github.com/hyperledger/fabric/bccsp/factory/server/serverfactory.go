package server

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/server"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

const (
	// BasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
	BasedFactoryName = "SERVER"
)

// Factory is the factory of the HSM-based BCCSP.
type Factory struct{}

// Name returns the name of this factory
func (f *Factory) Name() string {
	return BasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *Factory) Get(opts *server.Opts) (bccsp.BCCSP, error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid config. It must not be nil")
	}

	ks := sw.NewInMemoryKeyStore()
	return server.New(opts, ks)
}
