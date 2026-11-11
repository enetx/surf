package echretry_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"testing"

	"github.com/enetx/surf/internal/echretry"
	utls "github.com/enetx/utls"
)

func TestOnlyAuthenticatedTLSRejectionsSupplyConfigs(t *testing.T) {
	for _, err := range []error{&tls.ECHRejectionError{RetryConfigList: []byte{1, 2}},
		fmt.Errorf("wrapped: %w", &utls.ECHRejectionError{RetryConfigList: []byte{1, 2}})} {
		first := echretry.Configs(err)
		first[0] = 9
		if !bytes.Equal(echretry.Configs(err), []byte{1, 2}) {
			t.Fatal("result aliases TLS error metadata")
		}
	}
	for _, err := range []error{nil, errors.New("tls: server rejected ECH"), &tls.CertificateVerificationError{Err: errors.New("untrusted")}, &tls.ECHRejectionError{}} {
		if len(echretry.Configs(err)) != 0 {
			t.Fatalf("unauthorized retry for %T", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	input := []byte{1, 2}
	retry := echretry.WithConfig(ctx, input)
	input[0] = 9
	output := echretry.FromContext(retry)
	output[0] = 8
	if !bytes.Equal(echretry.FromContext(retry), []byte{1, 2}) || echretry.FromContext(ctx) != nil {
		t.Fatal("retry config ownership changed")
	}
	cancel()
	if !errors.Is(retry.Err(), context.Canceled) {
		t.Fatal("retry discarded cancellation")
	}
}
