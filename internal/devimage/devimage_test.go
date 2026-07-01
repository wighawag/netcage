package devimage_test

import (
	"strings"
	"testing"

	"github.com/wighawag/tooljail/internal/devimage"
)

// The default dev image is what `tooljail run` uses when the user does NOT pass a
// positional image, so a repo folder is useful out of the box. Like the
// redirector (ADR-0001, story 13) it MUST be pinned by an immutable @sha256:
// digest so runs are reproducible and no unaudited/mutable tag is pulled at run
// time. These guards mirror the redirector-pin tests so a future edit that
// re-introduces a mutable tag fails the gate loudly.

func TestImageReference_IsImmutableDigestNotMutableTag(t *testing.T) {
	ref := devimage.ImageReference()

	at := strings.Index(ref, "@")
	if at < 0 {
		t.Fatalf("default dev image reference %q has no @digest; it must be pinned by an immutable digest, not a mutable tag", ref)
	}

	repo := ref[:at]
	digest := ref[at+1:]

	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("default dev image reference %q is not pinned by sha256: digest", ref)
	}
	const hexLen = len("sha256:") + 64
	if len(digest) != hexLen {
		t.Fatalf("default dev image digest %q is not a full 64-hex sha256 digest (len %d, want %d)", digest, len(digest), hexLen)
	}
	for _, r := range digest[len("sha256:"):] {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			t.Fatalf("default dev image digest %q contains a non-hex character %q", digest, string(r))
		}
	}

	if strings.Contains(repo, ":") {
		t.Fatalf("default dev image reference %q carries a tag before the @digest (%q); pin by digest alone, no mutable tag", ref, repo)
	}
	if strings.Contains(strings.ToLower(ref), ":latest") {
		t.Fatalf("default dev image reference %q uses the mutable :latest tag", ref)
	}
}

// TestImageReference_IsABroadDevBase guards that the pinned digest points at the
// chosen broad, multi-language dev base (buildpack-deps: Debian + git + build
// toolchains), so the pin cannot silently drift to a different image.
func TestImageReference_IsABroadDevBase(t *testing.T) {
	ref := devimage.ImageReference()
	if !strings.Contains(ref, "buildpack-deps") {
		t.Fatalf("default dev image reference %q is not the buildpack-deps broad dev base", ref)
	}
}

// TestDigest_MatchesReference keeps the recorded digest and the assembled
// reference in lockstep, so the auditable digest constant cannot drift from what
// the run path consumes.
func TestDigest_MatchesReference(t *testing.T) {
	ref := devimage.ImageReference()
	if !strings.HasSuffix(ref, "@"+devimage.Digest) {
		t.Fatalf("reference %q does not end with the recorded digest %q", ref, devimage.Digest)
	}
}
