import { WebhookSignatureError } from "./errors";
import {
	type SchemeContext,
	verifyGitHub,
	verifyHmac,
	verifyStandardWebhooks,
	verifyStripe,
} from "./schemes";
import type { VerifyResult, VerifyWebhookOptions, WebhookScheme } from "./types";
import { normalizeHeaders, toBytes } from "./util";

const SCHEMES: readonly WebhookScheme[] = ["standard-webhooks", "stripe", "github", "hmac-sha256"];
const DEFAULT_TOLERANCE_SECONDS = 300;

function resolveScheme(
	scheme: WebhookScheme | undefined,
	provider: WebhookScheme | undefined,
): WebhookScheme {
	if (scheme !== undefined && provider !== undefined && scheme !== provider) {
		throw new TypeError("Pass either `scheme` or `provider`, not conflicting values for both");
	}
	const value: unknown = scheme ?? provider;
	if (typeof value === "string" && SCHEMES.includes(value as WebhookScheme)) {
		return value as WebhookScheme;
	}
	throw new WebhookSignatureError(
		"UNSUPPORTED_SCHEME",
		`Unsupported webhook scheme: ${typeof value === "string" ? value : typeof value}`,
	);
}

/**
 * Verifies a webhook signature against the RAW request body.
 *
 * Returns `{ ok: true, timestamp? }` on success and throws a `WebhookSignatureError`
 * with a typed `code` otherwise.
 *
 * @throws {WebhookSignatureError} when the request cannot be verified
 * @throws {TypeError} when the options themselves are invalid (programmer error)
 */
export function verifyWebhook(options: VerifyWebhookOptions): VerifyResult {
	const scheme = resolveScheme(options.scheme, options.provider);

	const toleranceSeconds = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
	if (
		typeof toleranceSeconds !== "number" ||
		Number.isNaN(toleranceSeconds) ||
		toleranceSeconds < 0
	) {
		throw new TypeError("toleranceSeconds must be a non-negative number");
	}

	const body: unknown = options.body;
	if (typeof body !== "string" && !(body instanceof Uint8Array)) {
		throw new TypeError("body must be the raw request body as a string or Uint8Array");
	}

	const headers: unknown = options.headers;
	if (headers === null || typeof headers !== "object") {
		throw new TypeError("headers must be a Headers instance or a record of header values");
	}

	const nowMs = (options.now ?? Date.now)();
	if (!Number.isFinite(nowMs)) {
		throw new TypeError("now() must return a finite number of milliseconds");
	}

	const ctx: SchemeContext = {
		headers: normalizeHeaders(options.headers),
		body: toBytes(body),
		secret: options.secret,
		toleranceSeconds,
		nowSeconds: Math.floor(nowMs / 1000),
		signatureHeader: options.signatureHeader,
		encoding: options.encoding ?? "hex",
	};

	switch (scheme) {
		case "standard-webhooks":
			return verifyStandardWebhooks(ctx);
		case "stripe":
			return verifyStripe(ctx);
		case "github":
			return verifyGitHub(ctx);
		case "hmac-sha256":
			return verifyHmac(ctx);
	}
}
