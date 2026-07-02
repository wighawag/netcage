package main

import "runtime/debug"

// version is the tooljail version string. For a GOReleaser build it is stamped
// via -ldflags "-X main.version=<tag>" (so a v0.1.0 tag becomes "0.1.0"). When it
// is left at the default "dev" (e.g. a plain `go build`, or `go install ...@vX`),
// resolveVersion falls back to the module version + VCS revision from the build
// info, so an installed binary still reports a real version.
var version = "dev"

// isVersionArg reports whether the argv requests the version (the `--version`
// flag or the `version` subcommand). `-v` is deliberately NOT accepted: it is
// already `--volume` in the run flag set, so only the unambiguous spellings are.
func isVersionArg(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "version")
}

// resolveVersion returns the version to print. It prefers the ldflags-stamped
// `version`; if that is still the "dev" default it derives one from the build
// info: the module version (set for `go install <module>@<version>`) and, when
// present, the short VCS revision.
func resolveVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		v = "dev"
	}
	if rev := vcsRevision(info); rev != "" {
		return v + " (" + rev + ")"
	}
	return v
}

// vcsRevision returns the short git revision from the build info settings, or ""
// if it is not embedded (e.g. a build from outside a VCS tree).
func vcsRevision(info *debug.BuildInfo) string {
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return rev
		}
	}
	return ""
}
