# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Security Model

`@yedoma-labs/tuyar-webhook` verifies webhook signatures on incoming HTTP requests. The security model assumes:

- **Secrets** are configured by the application owner and are trusted. They must never come from request data.
- **Headers and bodies** come from the network and are untrusted. They are only ever compared, never executed or used to build paths or queries.
- **Verification** runs per request, on the raw body that the sender signed.

## Security Features

1. **Constant-time comparison**: signatures are compared with `crypto.timingSafeEqual`, and every candidate is checked without early exit.
2. **Replay protection**: timestamped schemes (`standard-webhooks`, `stripe`) reject signed timestamps outside `toleranceSeconds` (default 300 s) in both directions.
3. **Secret validation**: `whsec_` secrets must be canonical base64 with a non-empty key. Empty secrets are rejected for every scheme.
4. **No secret leakage**: error messages never contain the secret or the signature material.
5. **Zero runtime dependencies**: only `node:crypto` is used.

## Known Limitations

- **No replay protection without a timestamp.** `github` and `hmac-sha256` carry no timestamp. Deduplicate on the delivery or event identifier in your application.
- **Raw body required.** If the body was parsed and re-serialized before verification, the check fails. This is a correctness issue, not a bypass, but it is the most common integration error. See the README.
- **Clock trust.** Timestamp checks rely on the verifying server's clock. Keep it synchronized (NTP).

## Reporting Vulnerabilities

Please report vulnerabilities privately through GitHub's private vulnerability reporting for `yedoma-labs/tuyar-webhook` (Security tab, "Report a vulnerability"), not in a public issue.

Please include:

- A description of the vulnerability and its impact
- Steps or a minimal test case to reproduce it
- A suggested fix, if you have one

We aim to respond within 48 hours and will coordinate disclosure.

## Dependency Security

The library has no runtime dependencies. Development dependencies are pinned in `pnpm-lock.yaml` and updated by Dependabot.

## License

MIT, see [LICENSE](LICENSE).
