# forward verb: connect-side connector is `nc` then `socat` (tool image), no mounted helper yet (2026-07-04)

The `internal/forward` wiring picks the socat connect side (spike Shape B) as
`podman --root <graphroot> exec -i <tool> sh -c 'exec nc 127.0.0.1 <port> || exec
socat STDIO TCP:127.0.0.1:<port>'`: try the tool's busybox `nc` (the spike proved
this works), fall back to the tool's `socat`. The spike's third fallback (mount a
static relay helper into the tool image, like netcage-dns into the sidecar) was
NOT built: `nc`-then-`socat` covers the common tool images and keeps the verb
self-contained. If a real tool image ships neither `nc` nor `socat`, the forward
will fail at connect time (a loud relay error, not a leak); the mounted-helper
fallback is the follow-up if that shows up in practice. Captured so the choice is
visible to a later reader.
