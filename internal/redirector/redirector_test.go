package redirector_test

import (
	"strings"
	"testing"

	"github.com/wighawag/tooljail/internal/redirector"
)

// The redirector is the jail's only route out (ADR-0001: the xjasonlyu/tun2socks
// sidecar). It MUST be pinned by an immutable @sha256: digest so runs are
// reproducible and no unaudited image is pulled at scan time (story 13). These
// guards assert that property holds for the reference the run path consumes, so
// a future edit that re-introduces a mutable tag fails the gate loudly.

func TestImageReference_IsImmutableDigestNotMutableTag(t *testing.T) {
	ref := redirector.ImageReference()

	at := strings.Index(ref, "@")
	if at < 0 {
		t.Fatalf("redirector reference %q has no @digest; it must be pinned by an immutable digest, not a mutable tag", ref)
	}

	repo := ref[:at]
	digest := ref[at+1:]

	// The pinned half must be a sha256 digest, never a tag.
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("redirector reference %q is not pinned by sha256: digest", ref)
	}
	const hexLen = len("sha256:") + 64
	if len(digest) != hexLen {
		t.Fatalf("redirector digest %q is not a full 64-hex sha256 digest (len %d, want %d)", digest, len(digest), hexLen)
	}
	for _, r := range digest[len("sha256:"):] {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			t.Fatalf("redirector digest %q contains a non-hex character %q", digest, string(r))
		}
	}

	// The repository half must NOT carry a mutable tag (no ":tag", and explicitly
	// not :latest). A bare repo before the @digest is what we want.
	if strings.Contains(repo, ":") {
		t.Fatalf("redirector reference %q carries a tag before the @digest (%q); pin by digest alone, no mutable tag", ref, repo)
	}
	if strings.Contains(strings.ToLower(ref), ":latest") {
		t.Fatalf("redirector reference %q uses the mutable :latest tag", ref)
	}
}

func TestImageReference_IsTheTun2socksRedirector(t *testing.T) {
	ref := redirector.ImageReference()
	// ADR-0001 pins the redirector to the xjasonlyu/tun2socks project; guard the
	// repository so the pinned digest cannot silently point at a different image.
	if !strings.Contains(ref, "xjasonlyu/tun2socks") {
		t.Fatalf("redirector reference %q is not the xjasonlyu/tun2socks image (ADR-0001)", ref)
	}
}

// TestRunPathConsumesPinnedReference asserts the reference the run path actually
// uses is EXACTLY the pinned, digest-bearing one. There must be no second,
// unpinned source of truth the run path could pull from instead.
func TestRunPathConsumesPinnedReference(t *testing.T) {
	runPathRef := redirector.RunPathImageReference()
	if runPathRef != redirector.ImageReference() {
		t.Fatalf("run path uses %q but the pinned reference is %q; the run path must consume exactly the pinned digest", runPathRef, redirector.ImageReference())
	}
	if !strings.Contains(runPathRef, "@sha256:") {
		t.Fatalf("run path reference %q is not digest-pinned; no run-path code may pull an unpinned image", runPathRef)
	}
}

// TestDigest_MatchesReference keeps the recorded digest and the assembled
// reference in lockstep, so the auditable digest constant cannot drift from what
// the run path consumes.
func TestDigest_MatchesReference(t *testing.T) {
	ref := redirector.ImageReference()
	if !strings.HasSuffix(ref, "@"+redirector.Digest) {
		t.Fatalf("reference %q does not end with the recorded digest %q", ref, redirector.Digest)
	}
}
