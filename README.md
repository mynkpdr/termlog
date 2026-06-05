# termlog

`termlog` is an authenticated terminal-session recorder. It
is a fork of Rust Asciinema 3.x that keeps Asciinema's PTY recording and playback
model, adds Google login, captures keyboard input, writes an asciicast
v2-compatible `.cast` file, and creates a local JWT receipt for verification.

The normal student workflow is offline-first. A backend server is not required
for recording or verification.

## What It Produces

For each audited recording, `termlog` writes:

```text
demo.cast
demo.cast.jwt
```

- `demo.cast` is an asciicast v2-compatible terminal recording. It can be played
  by `termlog play demo.cast` and by older `asciinema play demo.cast`.
- `demo.cast.jwt` is a receipt for the exact bytes of `demo.cast`. Verification
  fails if the recording or receipt is edited.

The recording includes terminal output and keyboard input. This is intentional
for exam audit use, but it means students must not type real passwords, tokens,
or other secrets inside an audited session.

## Student Workflow

Students receive the prebuilt `termlog` binary. They do not need a separate
Google OAuth JSON file or environment variables.

First-time setup:

```sh
termlog login
termlog whoami
```

Exam recording:

```sh
termlog rec demo.cast
# work normally in the shell
exit
```

Submit both generated files:

```text
demo.cast
demo.cast.jwt
```

`termlog login` opens the Google sign-in page in a browser when possible. If the
browser cannot be launched automatically, the command prints a URL. Open that URL
manually in a browser on the same machine/session; `termlog` waits for Google's
local callback.

After a successful Google login or token refresh, `termlog` allows recording with
the cached identity for 24 hours if network verification is temporarily
unavailable.

## TA Review Workflow

Verify the submitted files:

```sh
termlog verify demo.cast
```

Verify that the recording was made using the expected student email:

```sh
termlog verify demo.cast --expect-email student@example.edu
```

If the receipt is not named as the default sidecar:

```sh
termlog verify uploaded.cast receipt.jwt
```

Replay the recording:

```sh
termlog play demo.cast
```

For compatibility review, older Asciinema players can also replay the recording:

```sh
asciinema play demo.cast
```

## Verification Checks

`termlog verify` checks:

- the local receipt JWT signature,
- the SHA-256 hash and byte size of the `.cast` file,
- the proof metadata embedded in the cast header,
- the Google ID token issuer, audience, signature, expiry, and verified email,
- the expected Google OAuth client ID,
- the optional expected student email,
- the final `x` exit event,
- optional trusted timestamp anchors when available.

Verification output reports the Google identity-check mode:

- `online`: Google identity was checked using live Google JWKS.
- `cached`: live Google JWKS was unavailable, so cached JWKS was used.
- `skipped_no_network_no_cache`: neither live nor cached JWKS was available.
- `dev-mode`: the receipt was produced with `TERMLOG_ALLOW_DEV_AUTH=1`.

Development receipts are accepted only when the verifier also has
`TERMLOG_ALLOW_DEV_AUTH=1`.

## Audited Recording Rules

Audited `termlog rec` sessions:

- require a cached Google login before recording starts,
- force keyboard input capture,
- force asciicast v2-compatible output,
- reject append, raw, text, and asciicast v3 output,
- embed a `proof` object in the asciicast v2 header,
- write the receipt only after the final exit event has been flushed.

Use `TERMLOG_AUTH_CACHE_SECS` only for development or controlled testing if the
default 24-hour login cache window needs to be changed.

## Google OAuth Configuration

Official builds embed a Google Desktop OAuth client ID and secret at build time.
This keeps the student setup simple:

```sh
termlog login
```

The OAuth client secret is public once the binary is distributed. It should be
treated as build/package configuration, not as a security boundary. If the OAuth
client must be rotated, update the build secret and ship a new binary.

Runtime overrides are available for development, testing, or institutional
rebuilds. You may place a Google OAuth desktop-client JSON in the current user's
configuration directory:

```text
~/.config/termlog/google-client.json
```

`TERMLOG_CONFIG_HOME/google-client.json` is used when `TERMLOG_CONFIG_HOME` is
set. Otherwise `termlog` follows `XDG_CONFIG_HOME`, then falls back to
`~/.config/termlog`.

Or set:

```sh
TERMLOG_GOOGLE_CLIENT_JSON=/path/to/google-client.json
TERMLOG_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
TERMLOG_GOOGLE_CLIENT_SECRET=your-client-secret
```

## Optional Trusted Timestamp Anchors

Production audited recordings use DigiCert's public RFC3161 timestamp service by
default. `termlog` periodically hashes prior event-line bytes and requests a
timestamp token from the timestamp authority. The token is stored as a custom
asciicast v2 `"a"` event. Older Asciinema players ignore this event during
playback.

Recording continues if the timestamp authority, network, or `openssl` is
unavailable.

Useful settings:

```sh
TERMLOG_TSA_URL=http://timestamp.digicert.com
TERMLOG_TSA_INTERVAL_SECS=300
TERMLOG_DISABLE_TSA=1
```

Verification checks timestamp payload consistency and verifies timestamp tokens
when a CA file/path is available through `TERMLOG_TSA_CA_FILE`,
`TERMLOG_TSA_CA_PATH`, or the system `/etc/ssl/certs` directory.

## Build Requirements

`termlog` intentionally requires build-time secrets for Google OAuth and local
receipt signing. This prevents a fresh clone from accidentally building a
production-compatible binary with stale credentials from source code.

For local builds, either export the values:

```sh
export TERMLOG_GOOGLE_CLIENT_ID=your-google-desktop-client-id.apps.googleusercontent.com
export TERMLOG_GOOGLE_CLIENT_SECRET=your-google-desktop-client-secret
export TERMLOG_RECEIPT_SECRET=generate-a-long-random-receipt-signing-secret
```

Or create a local `.env` file from `.env.example`:

```sh
cp .env.example .env
$EDITOR .env
```

`.env` is ignored by git and must not be committed.

Build:

```sh
cargo build --release
```

The binary is produced at:

```text
target/release/termlog
```

To generate man pages and shell completions:

```sh
ASCIINEMA_GEN_DIR=/tmp/termlog-gen cargo build --release
```

## GitHub Actions Setup

Configure these repository secrets:

```text
TERMLOG_GOOGLE_CLIENT_ID
TERMLOG_GOOGLE_CLIENT_SECRET
TERMLOG_RECEIPT_SECRET
```

The CI and release workflows pass these secrets into `cargo build`; `build.rs`
embeds them into the binary. If you use GitHub Environment secrets instead of
repository secrets, attach the workflow jobs to that Environment in
`.github/workflows/*.yml`.

## Development Test Mode

For deterministic local tests without real Google sign-in:

```sh
TERMLOG_ALLOW_DEV_AUTH=1 termlog login
```

This creates a development identity. Do not enable this variable in production
exam launchers or TA verification environments.

## Security Model And Limitations

`termlog` provides tamper evidence for the submitted recording pair:

- the receipt binds a Google identity to a specific `.cast` hash and size,
- edits to the recording invalidate the receipt,
- `--expect-email` rejects recordings made with the wrong Google account,
- optional timestamp anchors can show that parts of the event stream existed near
  a trusted timestamp service time.

It does not provide hardware-backed attestation. A determined user who modifies
the binary or reverse-engineers the embedded receipt-signing key can forge
offline receipts. It also cannot observe activity outside the recorded terminal
session.

For stronger guarantees, use a backend signing service, managed exam machines,
account-level 2FA, and operational controls around the exam environment.

## License

`termlog` is a fork of Asciinema 3.x. The combined project is distributed under
GPL-3.0-or-later, inherited from upstream Asciinema. See [LICENSE](./LICENSE).

Copyright for original Asciinema code remains with its upstream authors.
Copyright for `termlog`-specific changes belongs to their respective authors.
