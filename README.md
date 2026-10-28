# @yedoma-labs/tuyar-webhook

<picture>
  <source media="(max-width: 640px)" srcset="https://raw.githubusercontent.com/yedoma-labs/assets/main/resized/banner-resized-mobile.png">
  <img src="https://raw.githubusercontent.com/yedoma-labs/assets/main/resized/banner-resized.png" alt="Project Header">
</picture>

[![CI](https://github.com/yedoma-labs/tuyar-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/yedoma-labs/tuyar-webhook/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@yedoma-labs/tuyar-webhook.svg)](https://www.npmjs.com/package/@yedoma-labs/tuyar-webhook)
[![TypeScript](https://img.shields.io/badge/TypeScript-6-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **туяр** (*tuyar*) — Yakutian (Sakha) for "(noch zu bestätigen)"

Zero-dependency webhook signature verification for **Standard Webhooks**, **Stripe**, **GitHub** and generic **HMAC-SHA256** schemes.
Built on `node:crypto` only, with raw-body safety, constant-time comparison, timestamp tolerance against replay, and secret rotation.

---

## Installation

```sh
pnpm add @yedoma-labs/tuyar-webhook
```

Requires Node.js 20 or newer.

---

## The raw body trap

A webhook signature is an HMAC over the exact bytes the sender transmitted. If anything re-encodes the body before you verify it, the check fails, even though the request is genuine:

- `express.json()` parses the body, and `JSON.stringify` then produces different whitespace, key order or escapes.
- `await request.json()` followed by re-serializing the object does the same.
- Charset or line-ending normalization changes bytes too.

**Always verify against the raw body, read before any parsing.** Use `express.raw()` in Express and `request.text()` in Next.js route handlers, and parse the JSON yourself only after `verifyWebhook` has succeeded.

```ts
// WRONG: the body was already re-serialized, verification fails
verifyWebhook({ scheme: "stripe", body: JSON.stringify(req.body), headers, secret });

// RIGHT: the untouched bytes that arrived on the wire
verifyWebhook({ scheme: "stripe", body: rawBody, headers, secret });
```

## Quickstart

### Express

```ts
import express from "express";
import { WebhookSignatureError, verifyWebhook } from "@yedoma-labs/tuyar-webhook";

const app = express();

// express.raw() must be mounted on this route before any express.json() middleware runs for it.
app.post(
	"/webhooks/stripe",
	express.raw({ type: "application/json" }),
	(req, res) => {
		try {
			verifyWebhook({
				scheme: "stripe",
				body: req.body, // Buffer with the untouched bytes
				headers: req.headers,
				secret: process.env.STRIPE_WEBHOOK_SECRET!,
			});
		} catch (error) {
			if (error instanceof WebhookSignatureError) {
				res.status(error.code === "MISSING_HEADER" ? 400 : 401).send(error.code);
				return;
			}
			throw error;
		}
		const event = JSON.parse(req.body.toString("utf8"));
		res.sendStatus(200);
	},
);
```

### Next.js (App Router)

```ts
// app/api/webhooks/github/route.ts
import { WebhookSignatureError, verifyWebhook } from "@yedoma-labs/tuyar-webhook";

export async function POST(request: Request): Promise<Response> {
	// Read the raw text once. Do not call request.json() as well: the body can only be read once.
	const body = await request.text();

	try {
		verifyWebhook({
			scheme: "github",
			body,
			headers: request.headers,
			secret: process.env.GITHUB_WEBHOOK_SECRET!,
		});
	} catch (error) {
		if (error instanceof WebhookSignatureError) {
			return new Response(error.code, { status: 401 });
		}
		throw error;
	}

	const event = JSON.parse(body);
	return new Response(null, { status: 204 });
}
```

### Fetch `Request` (Cloudflare Workers, Deno, Bun, Node 20+ handlers)

```ts
import { WebhookSignatureError, verifyWebhook } from "@yedoma-labs/tuyar-webhook";

export async function handle(request: Request): Promise<Response> {
	const body = new Uint8Array(await request.arrayBuffer());

	try {
		const result = verifyWebhook({
			scheme: "standard-webhooks",
			body,
			headers: request.headers,
			secret: process.env.WEBHOOK_SECRET!, // whsec_...
		});
		console.log("verified at", result.timestamp);
	} catch (error) {
		if (error instanceof WebhookSignatureError) {
			return new Response(error.code, { status: 401 });
		}
		throw error;
	}

	return new Response(null, { status: 200 });
}
```

## Supported schemes

| `scheme`           | Headers read                                                  | Signed content                           | Encoding | Timestamp |
| ------------------ | ------------------------------------------------------------- | ---------------------------------------- | -------- | --------- |
| `standard-webhooks`| `webhook-id`, `webhook-timestamp`, `webhook-signature`        | `${id}.${timestamp}.${body}`             | base64   | yes       |
| `stripe`           | `stripe-signature` (`t=…,v1=…`)                               | `${t}.${body}`                           | hex      | yes       |
| `github`           | `x-hub-signature-256` (`sha256=…`)                            | `body`                                   | hex      | no        |
| `hmac-sha256`      | the header named in `signatureHeader`                         | `body`                                   | hex or base64 | no   |

- **standard-webhooks**: the secret must have the form `whsec_<base64>`. The base64 part is the HMAC key. `webhook-signature` may hold several space-separated `v1,<base64>` entries.
- **stripe**: the secret is used as its UTF-8 bytes (`whsec_…` endpoint secret). Several `v1=` entries are accepted during rotation, and `v0=` entries are ignored.
- **github**: GitHub sends no timestamp, so `toleranceSeconds` does not apply (see replay protection below).
- **hmac-sha256**: a generic scheme. Set `signatureHeader` and optionally `encoding` (`"hex"` by default). The header may contain several values separated by commas or whitespace.

`provider` is accepted as an alias of `scheme`.

## API

```ts
verifyWebhook(options: {
	scheme?: "standard-webhooks" | "stripe" | "github" | "hmac-sha256";
	provider?: /* same values as scheme */;
	body: string | Uint8Array;                  // the RAW body
	headers: Headers | Record<string, string | readonly string[] | undefined>;
	secret: string | Uint8Array;
	toleranceSeconds?: number;                  // default 300
	now?: () => number;                         // milliseconds, default Date.now
	signatureHeader?: string;                   // required for hmac-sha256
	encoding?: "hex" | "base64";                // hmac-sha256 only, default "hex"
}): { ok: true; timestamp?: number };           // timestamp in Unix seconds
```

- Returns `{ ok: true, timestamp }` for schemes that carry a timestamp, and `{ ok: true }` otherwise.
- Header names are case-insensitive. `Headers` instances and plain records (such as Node's `req.headers`) both work.
- A string body is hashed as UTF-8.

### Errors

Verification failures throw `WebhookSignatureError`, which has a typed `code`:

| `code`                       | Meaning                                                              | Suggested HTTP status |
| ---------------------------- | -------------------------------------------------------------------- | --------------------- |
| `MISSING_HEADER`             | A required signature header is absent or empty                       | 400                   |
| `INVALID_SIGNATURE`          | No signature matches, or the header is malformed                     | 401                   |
| `TIMESTAMP_OUT_OF_TOLERANCE` | The signed timestamp is older or newer than `toleranceSeconds`        | 401                   |
| `MALFORMED_SECRET`           | The secret does not match the scheme's format                        | 500 (configuration)   |
| `UNSUPPORTED_SCHEME`         | The scheme name is unknown                                           | 500 (programming)     |

Invalid options (for example a negative `toleranceSeconds`, an `encoding` other than `"hex"` or `"base64"`, or a missing `signatureHeader`) throw a plain `TypeError`. Error messages never include the secret or the signature.

## Replay protection and rotation

- For `standard-webhooks` and `stripe`, a signed timestamp more than `toleranceSeconds` (default 300 s) away from `now()` is rejected in both directions. Lower the value if your clocks are reliable, and keep it above your expected clock skew.
- `github` and `hmac-sha256` carry no timestamp, so the library cannot stop a captured request from being replayed later. Deduplicate on the delivery identifier instead (for example the `X-GitHub-Delivery` header or the event ID in the payload).
- To rotate secrets, keep the old and new signatures in the header. Every `v1` entry (Stripe, Standard Webhooks) or every listed value (generic HMAC) is checked, and any match passes.

## Security notes

- Signatures are compared with `crypto.timingSafeEqual`. Only the digest length is checked first, which is fixed for SHA-256.
- Secrets are not trimmed. Make sure the value in your environment has no trailing newline.
- Verification only proves the request was signed with the secret. Always validate the payload you parse afterwards.

## Development

```sh
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

## License

MIT, see [LICENSE](LICENSE).
