// Package devimage pins tooljail's DEFAULT dev image by an immutable digest.
//
// When `tooljail run` is given NO positional image, it falls back to this broad,
// multi-language dev base so pointing tooljail at a repo folder is useful out of
// the box (prd jailed-interactive-repo-run, story 10: "a sensible DEFAULT dev
// image ... when I do not pass one"). Exactly like the redirector (ADR-0001,
// story 13) we pin by an immutable @sha256: digest rather than a mutable tag: a
// tag can be re-pushed to point at different bytes, a digest cannot, so runs are
// reproducible and no unaudited image is pulled at run time. The CLI's
// image-defaulting is the SINGLE source of truth for what the default is, so
// there is no code path that injects an unpinned default.
//
// Why buildpack-deps:bookworm as the default dev base: the untrusted-repo story
// is "clone the repo, install its deps, build it, run its tool" (git +
// pip/npm/go build/cargo build), all jailed. buildpack-deps is the official
// Debian image that carries git, curl, a C/C++ toolchain, and the common
// development headers/libraries repos build against, so a broad range of repos
// can be set up in it without tooljail building or maintaining its own image
// (which the prd explicitly defers: "A bespoke/owned default dev image
// (Containerfile) ... is a later decision"). It is a manifest-list (multi-arch)
// so the digest resolves on amd64 and arm64 alike. Language RUNTIMES beyond the
// build toolchain (a pinned python/node/go binary) are intentionally NOT baked
// in here; a repo that needs one installs it in its jailed setup step, or the
// user passes a more specific image (the positional image overrides this
// default).
//
// Provenance of the pinned digest (auditable):
//
//	Image:    docker.io/library/buildpack-deps   (broad Debian dev base)
//	Tag:      bookworm                            (current Debian stable at pin time)
//	Digest:   sha256:4efddd9a54ddc095e672b2fdf514f1ee4d3bb6e1f6ffc988b022c75e6ea99383
//	Obtained: 2026-07-01 from the Docker registry manifest API:
//
//	  TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/buildpack-deps:pull" | jq -r .token)
//	  curl -sI -H "Authorization: Bearer $TOKEN" \
//	    -H "Accept: application/vnd.oci.image.index.v1+json" \
//	    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
//	    "https://registry-1.docker.io/v2/library/buildpack-deps/manifests/bookworm" \
//	    | grep -i docker-content-digest
//	  # -> docker-content-digest: sha256:4efddd9a54ddc095e672b2fdf514f1ee4d3bb6e1f6ffc988b022c75e6ea99383
//
// To re-verify or re-pin: run the command above for the desired tag, confirm the
// digest, and update Tag + Digest together (the guard tests keep them in lockstep
// with the assembled reference).
package devimage

// Repository is the default dev image repository. It carries NO tag: the pin
// lives entirely in Digest, so the reference cannot resolve to a mutable tag.
const Repository = "docker.io/library/buildpack-deps"

// Tag records, for human/audit reference only, the release the pinned Digest
// corresponds to. It is intentionally NOT used to build the pull reference (a
// tag is mutable); ImageReference pins by Digest alone.
const Tag = "bookworm"

// Digest is the immutable content digest the default dev image is pinned to. See
// the package doc for how it was obtained and how to re-verify it.
const Digest = "sha256:4efddd9a54ddc095e672b2fdf514f1ee4d3bb6e1f6ffc988b022c75e6ea99383"

// ImageReference is the fully-pinned default dev image reference,
// repository@digest. This is the canonical reference for the default image;
// nothing in the project should construct the default any other way, so the CLI
// injects exactly this pinned, immutable reference when no image is passed.
func ImageReference() string {
	return Repository + "@" + Digest
}
