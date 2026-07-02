package main

import (
	"strings"
	"testing"
)

// TestIsVersionArg_AcceptsOnlyTheUnambiguousSpellings pins that only
// `netcage --version` and `netcage version` request the version, and crucially
// that `-v` does NOT (it is `--volume` in the run flag set, so accepting it here
// would collide). Extra args also disqualify it (e.g. `run -v x` is a real run).
func TestIsVersionArg_AcceptsOnlyTheUnambiguousSpellings(t *testing.T) {
	wantTrue := [][]string{
		{"--version"},
		{"version"},
	}
	for _, args := range wantTrue {
		if !isVersionArg(args) {
			t.Errorf("isVersionArg(%q) = false, want true", args)
		}
	}

	wantFalse := [][]string{
		{"-v"},                 // -v is --volume, NOT --version
		{"-V"},                 // not a spelling we accept
		{"--version", "extra"}, // only a lone version request counts
		{"run", "--version"},   // a flag inside a run is not a version request
		{"run", "-v", "a:b"},   // a real run using -v/--volume
		{"verify"},             // a real subcommand
		{},                     // no args
	}
	for _, args := range wantFalse {
		if isVersionArg(args) {
			t.Errorf("isVersionArg(%q) = true, want false", args)
		}
	}
}

// TestResolveVersion_PrefersLdflagsStamp checks that a build-time -X stamp (the
// GOReleaser path, version set to the tag) is returned verbatim, not overridden
// by the build-info fallback.
func TestResolveVersion_PrefersLdflagsStamp(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "0.1.0"
	if got := resolveVersion(); got != "0.1.0" {
		t.Fatalf("resolveVersion() = %q, want the ldflags stamp %q", got, "0.1.0")
	}
}

// TestResolveVersion_FallsBackWhenUnstamped checks that with the default "dev"
// stamp, resolveVersion derives a non-empty version from the build info (module
// version and/or VCS revision) rather than printing the bare "dev". Under `go
// test` the build info is present, so the result is at least non-empty and never
// the raw internal "(devel)" placeholder.
func TestResolveVersion_FallsBackWhenUnstamped(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "dev"
	got := resolveVersion()
	if got == "" {
		t.Fatal("resolveVersion() with an unstamped build must not be empty")
	}
	if strings.Contains(got, "(devel)") {
		t.Fatalf("resolveVersion() = %q leaked the raw (devel) placeholder", got)
	}
}
