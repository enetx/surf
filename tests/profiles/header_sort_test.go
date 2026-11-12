package profiles_test

import (
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

func TestSortByOrderCaseAndUnknownFields(t *testing.T) {
	t.Parallel()
	cache := profiles.NewHeaderCache(g.Map[string, g.Slice[string]]{
		"GET": {"First", "SECOND"},
	}, nil)
	fields := g.NewMapOrd[string, string]()
	for _, name := range []string{"z-unknown", "second", "a-unknown", "fIrSt"} {
		fields.Insert(name, name)
	}
	profiles.SortByOrder(&fields, "CUSTOM", cache.Enums(false))
	require.Equal(t, g.Slice[string]{"fIrSt", "second", "a-unknown", "z-unknown"}, fields.Keys())
	for _, name := range fields.Keys() {
		require.Equal(t, name, fields.Get(name).Unwrap(), "sorting changes no caller values")
	}
}
