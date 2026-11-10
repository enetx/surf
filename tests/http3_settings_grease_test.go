package surf_test

import (
	"errors"
	"fmt"
	_http "net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	chromequic "github.com/enetx/surf/profiles/chrome/quic"
	"github.com/stretchr/testify/require"
)

func TestHTTP3SettingsGreaseFreshConnectionsAndReuse(t *testing.T) {
	server, udp, origin, err := createHTTP3TestServer(func(w _http.ResponseWriter, _ *_http.Request) {
		fmt.Fprint(w, "ok")
	})
	require.NoError(t, err)
	go server.Serve(udp)
	defer server.Close()
	defer udp.Close()
	var calls atomic.Uint64
	client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().
		HTTP3Settings().
		GreaseFactory(func() (uint64, uint64, error) { return 64, calls.Add(1), nil }).
		Set().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	for connection := uint64(1); connection <= 3; connection++ {
		for range 2 {
			response := client.Get(g.String(origin)).Do()
			require.False(t, response.IsErr(), "connection %d: %v", connection, response.Err())
			require.Equal(t, 3, response.Ok().GetResponse().ProtoMajor)
			require.Equal(t, g.String("ok"), response.Ok().Body.String().Unwrap())
			require.Equal(t, connection, calls.Load())
		}
		client.GetClient().CloseIdleConnections()
	}
}

func TestHTTP3SettingsGreaseDisableAndFailure(t *testing.T) {
	peer := newH3Peer(t)
	builder := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3()
	h := builder.HTTP3Settings().GreaseFactory(nil)
	client := h.Set().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	captured := peer.request(t, client)
	for _, setting := range captured.settings {
		require.False(t, setting.id >= 33 && (setting.id-33)%31 == 0)
	}
	failure := errors.New("cannot generate SETTINGS")
	failed := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().
		HTTP3Settings().
		GreaseFactory(func() (uint64, uint64, error) { return 0, 0, failure }).
		Set().Timeout(5 * time.Second).Build().Unwrap()
	defer failed.Close()
	result := failed.Get(g.String(peer.url)).Do()
	require.True(t, result.IsErr())
	require.ErrorIs(t, result.Err(), failure)
}

func TestChromiumSettingsGreaseRange(t *testing.T) {
	for range 1000 {
		id, value, err := chromequic.NewSettingsGrease()
		require.NoError(t, err)
		require.GreaterOrEqual(t, id, uint64(33))
		require.Zero(t, (id-33)%31)
		require.LessOrEqual(t, (id-33)/31, uint64(0xffffffff))
		require.LessOrEqual(t, value, uint64(0xffffffff))
	}
}
