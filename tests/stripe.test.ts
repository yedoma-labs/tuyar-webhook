import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookSignatureError } from "../src/index";
import { BODY, hmacHex, NOW_MS, NOW_SECONDS, STRIPE_SECRET, signStripe } from "./helpers";

function verify(
	overrides: Partial<Parameters<typeof verifyWebhook>[0]> & {
		headers?: Record<string, string | undefined>;
	} = {},
) {
	return verifyWebhook({
		scheme: "stripe",
		body: BODY,
		headers: { "stripe-signature": signStripe(STRIPE_SECRET, NOW_SECONDS, BODY) },
		secret: STRIPE_SECRET,
		now: () => NOW_MS,
		...overrides,
	});
}

function expectCode(fn: () => unknown, code: string): void {
	try {
		fn();
	} catch (error) {
		expect(error).toBeInstanceOf(WebhookSignatureError);
		expect((error as WebhookSignatureError).code).toBe(code);
		return;
	}
	throw new Error(`expected ${code} to be thrown`);
}

describe("stripe", () => {
	it("accepts a valid signature and returns the timestamp", () => {
		expect(verify()).toEqual({ ok: true, timestamp: NOW_SECONDS });
	});

	it("accepts a hardcoded reference vector", () => {
		const result = verifyWebhook({
			scheme: "stripe",
			body: BODY,
			headers: {
				"stripe-signature": `t=1700000000,v1=${hmacHex(STRIPE_SECRET, `1700000000.${BODY}`)}`,
			},
			secret: STRIPE_SECRET,
			now: () => NOW_MS,
		});
		expect(result).toEqual({ ok: true, timestamp: NOW_SECONDS });
	});

	it("accepts any matching v1 in a rotated header and ignores v0", () => {
		const valid = signStripe(STRIPE_SECRET, NOW_SECONDS, BODY).split(",")[1];
		const header = `t=${NOW_SECONDS},v0=deadbeef,v1=${"0".repeat(64)},${valid}`;
		expect(verify({ headers: { "stripe-signature": header } }).ok).toBe(true);
	});

	it("reads the signature header case-insensitively", () => {
		const headers = new Headers({
			"Stripe-Signature": signStripe(STRIPE_SECRET, NOW_SECONDS, BODY),
		});
		expect(verify({ headers }).ok).toBe(true);
	});

	it("throws MISSING_HEADER when stripe-signature is absent", () => {
		expectCode(() => verify({ headers: {} }), "MISSING_HEADER");
	});

	it("throws INVALID_SIGNATURE when t is missing", () => {
		const v1 = signStripe(STRIPE_SECRET, NOW_SECONDS, BODY).split(",")[1];
		expectCode(() => verify({ headers: { "stripe-signature": v1 } }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when no v1 entry is present", () => {
		expectCode(
			() => verify({ headers: { "stripe-signature": `t=${NOW_SECONDS},v0=abc` } }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE for a non-numeric timestamp", () => {
		expectCode(
			() => verify({ headers: { "stripe-signature": `t=abc,v1=${"0".repeat(64)}` } }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE for a wrong signature", () => {
		expectCode(
			() => verify({ headers: { "stripe-signature": `t=${NOW_SECONDS},v1=${"a".repeat(64)}` } }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE for a non-hex signature", () => {
		expectCode(
			() => verify({ headers: { "stripe-signature": `t=${NOW_SECONDS},v1=zz` } }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE when the body was modified", () => {
		expectCode(() => verify({ body: BODY.replace("ping", "pong") }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the raw body is replaced by a parsed and re-serialized body", () => {
		const raw = '{ "id": "evt_1",\n  "type": "ping" }';
		const headers = { "stripe-signature": signStripe(STRIPE_SECRET, NOW_SECONDS, raw) };
		expect(verify({ body: raw, headers }).ok).toBe(true);
		expectCode(
			() => verify({ body: JSON.stringify(JSON.parse(raw)), headers }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws TIMESTAMP_OUT_OF_TOLERANCE for an expired timestamp", () => {
		const old = NOW_SECONDS - 301;
		expectCode(
			() => verify({ headers: { "stripe-signature": signStripe(STRIPE_SECRET, old, BODY) } }),
			"TIMESTAMP_OUT_OF_TOLERANCE",
		);
	});

	it("throws TIMESTAMP_OUT_OF_TOLERANCE for a timestamp in the future", () => {
		const future = NOW_SECONDS + 301;
		expectCode(
			() => verify({ headers: { "stripe-signature": signStripe(STRIPE_SECRET, future, BODY) } }),
			"TIMESTAMP_OUT_OF_TOLERANCE",
		);
	});

	it("throws MALFORMED_SECRET for an empty secret", () => {
		expectCode(() => verify({ secret: "" }), "MALFORMED_SECRET");
	});

	it("accepts a Uint8Array secret that matches the UTF-8 secret", () => {
		expect(verify({ secret: new TextEncoder().encode(STRIPE_SECRET) }).ok).toBe(true);
	});
});
