// Package echretry carries authenticated ECH retry metadata for one connection
// attempt. It never changes DNS caches or allows an unencrypted retry.
package echretry

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"

	utls "github.com/enetx/utls"
)

// Configs only accepts the TLS engines' authenticated rejection errors.
// Certificate, transport and policy failures never authorize a retry.
// https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.6
func Configs(err error) []byte {
	if rejection, ok := errors.AsType[*tls.ECHRejectionError](err); ok {
		return slices.Clone(rejection.RetryConfigList)
	}

	if rejection, ok := errors.AsType[*utls.ECHRejectionError](err); ok {
		return slices.Clone(rejection.RetryConfigList)
	}

	return nil
}

type configKey struct{}

func WithConfig(ctx context.Context, config []byte) context.Context {
	return context.WithValue(ctx, configKey{}, slices.Clone(config))
}

func FromContext(ctx context.Context) []byte {
	config, _ := ctx.Value(configKey{}).([]byte)
	return slices.Clone(config)
}
