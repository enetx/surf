package origin_test

import (
	"net/url"
	"testing"

	"github.com/enetx/surf/internal/origin"
	"github.com/stretchr/testify/require"
)

func TestOriginKey(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://EXAMPLE.com:00443/path?x=1", "https://example.com"},
		{"http://example.com:080/", "http://example.com"},
		{"https://example.com:8443/", "https://example.com:8443"},
		{"https://bücher.example/", "https://xn--bcher-kva.example"},
		{"https://user:password@example.com/", "https://example.com"},
		{"https://[0:0:0:0:0:0:0:1]:443/", "https://[::1]"},
		{"https://[::1]:8443/", "https://[::1]:8443"},
		{"ftp://example.com/", ""},
		{"https://example.com:65536/", ""},
		{"https:///", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			u, err := url.Parse(tc.input)
			require.NoError(t, err)
			got, valid := origin.Key(u)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.want != "", valid)
		})
	}
	key, valid := origin.Key(nil)
	require.Empty(t, key)
	require.False(t, valid)
}
