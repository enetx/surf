package surf_test

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func TestHTTP3EarlyDataRacingRejectionAnd425(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, mode := range []string{"accepted", "rejected", "425"} {
			t.Run(browser+"/"+mode, func(t *testing.T) {
				var reject atomic.Bool
				sent := make(chan struct{})
				origin, observed := earlyDataServer(t, &reject, mode == "425", sent)
				var once sync.Once
				cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 8)}
				b := racingBuilder(browser)
				b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { once.Do(func() { close(sent) }) }}
				}).Set()
				client := b.HTTP3Settings().ConnectionRacing(true).EarlyData(true).Set().
					TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).Timeout(10 * time.Second).Build().Unwrap()
				defer client.Close()
				warmEarlyRacing(t, client, cache, origin)
				<-observed
				reject.Store(mode == "rejected")
				r := client.Get(g.String(origin)).Do()
				require.False(t, r.IsErr(), "%v", r.Err())
				r.Ok().Body.String().Unwrap()
				got := <-observed
				require.Equal(t, "GET", got.method)
				require.Equal(t, mode != "rejected", got.early)
				if mode == "425" {
					retry := <-observed
					require.False(t, retry.early)
					require.Equal(t, 425, r.Ok().GetResponse().StatusCode)
				}
			})
		}
	}
}
