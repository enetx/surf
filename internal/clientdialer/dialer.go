// Package clientdialer identifies Surf's default TCP dial functions.
package clientdialer

import (
	"context"
	"net"
	"reflect"
)

type adapter struct{ dialer *net.Dialer }

// Wrap retains the dialer and returns a function identifiable as Surf's default.
func Wrap(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return adapter{dialer}.dialContext
}

func (d adapter) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

// IsDefault reports whether dial came from Wrap. DNS address reuse must not
// replace resolution inside an application-supplied dial function.
func IsDefault(dial func(context.Context, string, string) (net.Conn, error)) bool {
	return dial != nil && reflect.ValueOf(dial).Pointer() == reflect.ValueOf(adapter{}.dialContext).Pointer()
}
