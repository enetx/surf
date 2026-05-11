package profiles_test

import (
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
)

func TestOSKeyIsMobile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key  profiles.OSKey
		name string
		want bool
	}{
		{profiles.Windows, "Windows", false},
		{profiles.MacOS, "MacOS", false},
		{profiles.Linux, "Linux", false},
		{profiles.Android, "Android", true},
		{profiles.IOS, "IOS", true},
	}

	for _, c := range cases {
		if got := c.key.IsMobile(); got != c.want {
			t.Errorf("%s.IsMobile() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOSKeyMobile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key  profiles.OSKey
		name string
		want g.String
	}{
		{profiles.Windows, "Windows", "?0"},
		{profiles.MacOS, "MacOS", "?0"},
		{profiles.Linux, "Linux", "?0"},
		{profiles.Android, "Android", "?1"},
		{profiles.IOS, "IOS", "?1"},
	}

	for _, c := range cases {
		if got := c.key.Mobile(); got != c.want {
			t.Errorf("%s.Mobile() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHeaderCacheLazyInit(t *testing.T) {
	t.Parallel()

	desktop := g.Map[string, g.Slice[string]]{
		"GET":  {"a", "b", "c"},
		"POST": {"x", "y"},
	}
	mobile := g.Map[string, g.Slice[string]]{
		"GET":  {"a", "b"},
		"POST": {"x"},
	}

	cache := profiles.NewHeaderCache(desktop, mobile)

	desktopEnums := cache.Enums(false)
	if desktopEnums.Get("GET").IsNone() {
		t.Fatal("desktop GET enum missing")
	}
	getEnum := desktopEnums.Get("GET").Unwrap()
	if getEnum.Get("a").UnwrapOrDefault() != 0 {
		t.Errorf("desktop GET 'a' position = %d, want 0", getEnum.Get("a").UnwrapOrDefault())
	}
	if getEnum.Get("c").UnwrapOrDefault() != 2 {
		t.Errorf("desktop GET 'c' position = %d, want 2", getEnum.Get("c").UnwrapOrDefault())
	}

	mobileEnums := cache.Enums(true)
	if mobileEnums.Get("GET").IsNone() {
		t.Fatal("mobile GET enum missing")
	}
	mobileGet := mobileEnums.Get("GET").Unwrap()
	if mobileGet.Get("a").UnwrapOrDefault() != 0 {
		t.Errorf("mobile GET 'a' position = %d, want 0", mobileGet.Get("a").UnwrapOrDefault())
	}
	if !mobileGet.Get("c").IsNone() {
		t.Error("mobile GET should not contain 'c'")
	}
}

func TestHeaderCacheCachesResult(t *testing.T) {
	t.Parallel()

	desktop := g.Map[string, g.Slice[string]]{
		"GET": {"a", "b"},
	}
	mobile := g.Map[string, g.Slice[string]]{
		"GET": {"a"},
	}

	cache := profiles.NewHeaderCache(desktop, mobile)

	first := cache.Enums(false)
	second := cache.Enums(false)

	if first.Get("GET").Unwrap().Get("a").UnwrapOrDefault() != second.Get("GET").Unwrap().Get("a").UnwrapOrDefault() {
		t.Error("repeated Enums(false) calls returned inconsistent enums")
	}
}

