// Package redirector pins the netcage redirector image by an immutable digest.
//
// The redirector is the jail's ONLY route out (CONTEXT.md: "redirector";
// ADR-0001: a tun2socks / gVisor-netstack sidecar, the xjasonlyu/tun2socks
// project). Story 13 requires it be vendored/pinned so runs are reproducible and
// no unaudited image is pulled at scan time. We pin by an immutable @sha256:
// digest rather than a mutable tag (:latest or a bare version tag): a tag can be
// re-pushed to point at different bytes, a digest cannot. The run path (the
// jail-run-forced-egress task) consumes ImageReference()/RunPathImageReference()
// as its SINGLE source of truth for what to pull, so there is no code path that
// can pull an unpinned image.
//
// Auditing the pin (how the digest was obtained, for a reviewer): see the
// Repository/Tag/Digest constants below and the provenance recorded in the
// package doc here. The digest is the registry's Docker-Content-Digest for the
// release tag, which is exactly what a `podman pull` resolves and verifies the
// pulled bytes against.
//
// Provenance of the pinned digest (auditable):
//
//	Image:    docker.io/xjasonlyu/tun2socks   (ADR-0001's chosen redirector)
//	Tag:      v2.6.0                           (latest stable release at pin time)
//	Digest:   sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107
//	Obtained: 2026-06-30 from the Docker registry manifest API, cross-checked
//	          against the Docker Hub tags API:
//
//	  TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:xjasonlyu/tun2socks:pull" | jq -r .token)
//	  curl -sI -H "Authorization: Bearer $TOKEN" \
//	    -H "Accept: application/vnd.oci.image.index.v1+json" \
//	    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
//	    "https://registry-1.docker.io/v2/xjasonlyu/tun2socks/manifests/v2.6.0" \
//	    | grep -i docker-content-digest
//	  # -> docker-content-digest: sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107
//
// To re-verify or re-pin: run the command above for the desired tag, confirm the
// digest, and update Tag + Digest together (the guard tests keep them in lockstep
// with the assembled reference).
package redirector

// Repository is the redirector image repository (ADR-0001: xjasonlyu/tun2socks).
// It carries NO tag: the pin lives entirely in Digest, so the reference cannot
// resolve to a mutable tag.
const Repository = "docker.io/xjasonlyu/tun2socks"

// Tag records, for human/audit reference only, the release the pinned Digest
// corresponds to. It is intentionally NOT used to build the pull reference (a
// tag is mutable); ImageReference pins by Digest alone.
const Tag = "v2.6.0"

// Digest is the immutable content digest the redirector is pinned to. See the
// package doc for how it was obtained and how to re-verify it.
const Digest = "sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107"

// ImageReference is the fully-pinned redirector reference, repository@digest.
// This is the canonical reference for the redirector image; nothing in the
// project should construct a redirector reference any other way.
func ImageReference() string {
	return Repository + "@" + Digest
}

// RunPathImageReference is what the run path (the jail's sidecar wiring) pulls
// and runs. It is deliberately identical to ImageReference so the run path has
// exactly ONE, digest-pinned source of truth: there is no unpinned/mutable-tag
// reference anywhere for the run path to fall back to.
func RunPathImageReference() string {
	return ImageReference()
}
