# Redirector image pin (digest record)

The redirector (ADR-0001: the `xjasonlyu/tun2socks` sidecar) is pinned by an
immutable digest so runs are reproducible and no unaudited image is pulled at
scan time (story 13). This file is the human-auditable record of WHAT is pulled;
the machine source of truth the run path consumes is
`internal/redirector/redirector.go` (constants `Repository`, `Tag`, `Digest`),
kept in lockstep with this record by the guard tests in
`internal/redirector/redirector_test.go`.

## What is pinned

| Field    | Value |
| -------- | ----- |
| Image    | `docker.io/xjasonlyu/tun2socks` |
| Tag      | `v2.6.0` (latest stable release at pin time; recorded for audit only, NOT used to pull) |
| Digest   | `sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107` |
| Pull ref | `docker.io/xjasonlyu/tun2socks@sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107` |

The run path pulls the **digest** reference only. The tag is never used to
resolve the image (a tag is mutable; a digest is not), so re-pushing `v2.6.0` or
`:latest` upstream cannot change the bytes tooljail runs.

## How the digest was obtained (re-verifiable)

Captured 2026-06-30 from the Docker registry manifest API (the registry's
`Docker-Content-Digest` is exactly what a `podman pull` resolves and verifies the
pulled bytes against), cross-checked against the Docker Hub tags API:

```sh
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:xjasonlyu/tun2socks:pull" | jq -r .token)
curl -sI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
  "https://registry-1.docker.io/v2/xjasonlyu/tun2socks/manifests/v2.6.0" \
  | grep -i docker-content-digest
# -> docker-content-digest: sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107
```

The digest is the multi-arch manifest-list (image index) digest, so the same
pinned reference resolves to the correct per-architecture image on each host.

## Re-pinning

To move to a new release: run the command above for the desired tag, confirm the
returned digest, then update `Tag` + `Digest` together in
`internal/redirector/redirector.go` and the table above. The guard tests fail if
the digest is not a full immutable `@sha256:` digest or drifts from the assembled
reference.
