package origin_test

import (
	"net/url"
	"testing"

	"github.com/enetx/surf/internal/origin"
	"github.com/stretchr/testify/require"
)

func TestTrustworthyHTTP(t *testing.T) {
	t.Parallel()
	require.False(t, origin.TrustworthyHTTP(nil))
	for _, tc := range []struct {
		url     string
		trusted bool
	}{
		{"https://example.com/", true},
		{"HTTPS://EXAMPLE.COM/", true},
		{"http://example.com/", false},
		{"http://192.168.0.1/", false},
		{"http://127.0.0.1/", true},
		{"http://127.9.8.7:8080/", true},
		{"http://[::1]/", true},
		{"http://[::ffff:127.0.0.1]/", false},
		{"http://[::2]/", false},
		{"http://localhost/", true},
		{"http://LOCALHOST.:8080/", true},
		{"http://a.localhost/", true},
		{"http://a.localhost./", true},
		{"http://localhost.example/", false},
		{"http://notlocalhost/", false},
		{"http://localhost../", false},
		{"http://example.onion/", false},
		{"ftp://localhost/", false},
		{"https:///path", false},
		{"/relative", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			require.Equal(t, tc.trusted, origin.TrustworthyHTTP(u))
		})
	}
}
