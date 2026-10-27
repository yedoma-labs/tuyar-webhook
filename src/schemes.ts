import { WebhookSignatureError } from "./errors";
import type { VerifyResult, WebhookScheme } from "./types";
import {
	decodeBase64,
	decodeHex,
	type HeaderMap,
	hmacSha256,
	matchesAny,
	parseUnixSeconds,
	requireHeader,
} from "./util";

/** Normalized, already validated input shared by all scheme implementations. */
export interface SchemeContext {
	readonly headers: HeaderMap;
	readonly body: Uint8Array;
	readonly secret: string | Uint8Array;
	readonly toleranceSeconds: number;
	readonly nowSeconds: number;
	readonly signatureHeader: string | undefined;
	readonly encoding: "hex" | "base64";
}

const WHSEC_PREFIX = "whsec_";
const GITHUB_PREFIX = "sha256=";

function invalidSignature(): WebhookSignatureError {
	return new WebhookSignatureError("INVALID_SIGNATURE", "Webhook signature verification failed");
}

function malformedSecret(scheme: WebhookScheme, detail: string): WebhookSignatureError {
	return new WebhookSignatureError(
		"MALFORMED_SECRET",
		`Malformed secret for scheme "${scheme}": ${detail}`,
	);
}

/** Raw HMAC key: a non-empty string (UTF-8) or a non-empty byte array. */
function rawKey(secret: string | Uint8Array, scheme: WebhookScheme): Uint8Array {
	if (typeof secret === "string") {
		if (secret.length > 0) return Buffer.from(secret, "utf8");
	} else if (secret instanceof Uint8Array && secret.byteLength > 0) {
		return secret;
	}
	throw malformedSecret(scheme, "expected a non-empty string or Uint8Array");
}

/** Standard Webhooks secret: `whsec_<base64>`, the base64 part is the HMAC key. */
function standardWebhooksKey(secret: string | Uint8Array): Uint8Array {
	const expected = "expected a string of the form whsec_<base64>";
	if (typeof secret !== "string" || !secret.startsWith(WHSEC_PREFIX)) {
		throw malformedSecret("standard-webhooks", expected);
	}
	const key = decodeBase64(secret.slice(WHSEC_PREFIX.length));
	if (key === undefined || key.byteLength === 0) {
		throw malformedSecret("standard-webhooks", expected);
	}
	return key;
}

function assertWithinTolerance(timestamp: number, ctx: SchemeContext): void {
	if (Math.abs(ctx.nowSeconds - timestamp) > ctx.toleranceSeconds) {
		throw new WebhookSignatureError(
			"TIMESTAMP_OUT_OF_TOLERANCE",
			"Webhook timestamp is outside the allowed tolerance",
		);
	}
}

/**
 * Standard Webhooks: signs `${webhook-id}.${webhook-timestamp}.${body}` with HMAC-SHA256.
 * `webhook-signature` is a space-separated list of `v1,<base64>` entries.
 */
export function verifyStandardWebhooks(ctx: SchemeContext): VerifyResult {
	const id = requireHeader(ctx.headers, "webhook-id");
	const timestampRaw = requireHeader(ctx.headers, "webhook-timestamp");
	const signatureHeader = requireHeader(ctx.headers, "webhook-signature");
	const key = standardWebhooksKey(ctx.secret);

	const timestamp = parseUnixSeconds(timestampRaw);
	if (timestamp === undefined) throw invalidSignature();

	const candidates = signatureHeader.split(/\s+/).flatMap((entry) => {
		const separator = entry.indexOf(",");
		if (separator === -1 || entry.slice(0, separator) !== "v1") return [];
		return [decodeBase64(entry.slice(separator + 1))];
	});
	if (candidates.length === 0) throw invalidSignature();

	const signed = Buffer.concat([Buffer.from(`${id}.${timestampRaw}.`, "utf8"), ctx.body]);
	if (!matchesAny(hmacSha256(key, signed), candidates)) throw invalidSignature();

	assertWithinTolerance(timestamp, ctx);
	return { ok: true, timestamp };
}

/**
 * Stripe: `stripe-signature` is `t=<unix>,v1=<hex>[,v1=<hex>...]`.
 * The signed payload is `${t}.${body}`.
 */
export function verifyStripe(ctx: SchemeContext): VerifyResult {
	const header = requireHeader(ctx.headers, "stripe-signature");

	let timestampRaw: string | undefined;
	const candidates: (Buffer | undefined)[] = [];
	for (const part of header.split(",")) {
		const separator = part.indexOf("=");
		if (separator === -1) continue;
		const name = part.slice(0, separator).trim();
		const value = part.slice(separator + 1).trim();
		if (name === "t" && timestampRaw === undefined) timestampRaw = value;
		if (name === "v1") candidates.push(decodeHex(value));
	}
	if (timestampRaw === undefined || candidates.length === 0) throw invalidSignature();

	const timestamp = parseUnixSeconds(timestampRaw);
	if (timestamp === undefined) throw invalidSignature();

	const key = rawKey(ctx.secret, "stripe");
	const signed = Buffer.concat([Buffer.from(`${timestampRaw}.`, "utf8"), ctx.body]);
	if (!matchesAny(hmacSha256(key, signed), candidates)) throw invalidSignature();

	assertWithinTolerance(timestamp, ctx);
	return { ok: true, timestamp };
}

/** GitHub: `x-hub-signature-256` is `sha256=<hex>` over the raw body. GitHub sends no timestamp. */
export function verifyGitHub(ctx: SchemeContext): VerifyResult {
	const header = requireHeader(ctx.headers, "x-hub-signature-256");
	if (!header.startsWith(GITHUB_PREFIX)) throw invalidSignature();

	const key = rawKey(ctx.secret, "github");
	const candidate = decodeHex(header.slice(GITHUB_PREFIX.length));
	if (!matchesAny(hmacSha256(key, ctx.body), [candidate])) throw invalidSignature();

	return { ok: true };
}

/**
 * Generic HMAC-SHA256 over the raw body. The signature header may hold several
 * values separated by commas or whitespace (for secret rotation).
 */
export function verifyHmac(ctx: SchemeContext): VerifyResult {
	const name = ctx.signatureHeader?.trim();
	if (name === undefined || name === "") {
		throw new TypeError('The "hmac-sha256" scheme requires the "signatureHeader" option');
	}
	const header = requireHeader(ctx.headers, name);

	const decode = ctx.encoding === "base64" ? decodeBase64 : decodeHex;
	const candidates = header
		.split(/[\s,]+/)
		.filter((part) => part.length > 0)
		.map((part) => decode(part));
	if (candidates.length === 0) throw invalidSignature();

	const key = rawKey(ctx.secret, "hmac-sha256");
	if (!matchesAny(hmacSha256(key, ctx.body), candidates)) throw invalidSignature();

	return { ok: true };
}
