package quictransport

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDialerSharedSocketLifecycle(t *testing.T) {
	for _, lazy := range []bool{false, true} {
		name := "eager"
		if lazy {
			name = "lazy"
		}
		t.Run(name, func(t *testing.T) {
			dialer := &Dialer{Lazy: lazy}
			t.Cleanup(dialer.Close)
			require.NoError(t, dialer.Init())
			if lazy {
				require.Nil(t, dialer.socket, "TCP-first discovery must not allocate UDP yet")
			}

			const workers = 16
			transports := make(chan *quic.Transport, workers)
			errors := make(chan error, workers)
			var group sync.WaitGroup
			for range workers {
				group.Go(func() {
					transport, err := dialer.sharedQUICTransport()
					if err != nil {
						errors <- err
						return
					}
					transports <- transport
				})
			}
			group.Wait()
			close(transports)
			close(errors)
			for err := range errors {
				require.NoError(t, err)
			}
			require.Len(t, transports, workers)
			for transport := range transports {
				require.Same(t, dialer.transport, transport, "concurrent attempts share one socket")
			}

			dialer.Close()
			_, err := dialer.sharedQUICTransport()
			require.ErrorIs(t, err, net.ErrClosed)
			require.ErrorIs(t, dialer.socket.SetReadDeadline(time.Now().Add(time.Second)), net.ErrClosed)
		})
	}
}
