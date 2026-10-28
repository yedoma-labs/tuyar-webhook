import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookSignatureError } from "../src/index";
import { BODY, HMAC_SECRET, hmacBase64, hmacHex, NOW_MS } from "./helpers";

const HEADER = "X-Signature";

function verify(
	overrides: Partial<Parameters<typeof verifyWebhook>[0]> & {
		headers?: Record<string, string | undefined>;
	} = {},
) {
	return verifyWebhook({
		scheme: "hmac-sha256",
		body: BODY,
		headers: { [HEADER]: hmacHex(HMAC_SECRET, BODY) },
		secret: HMAC_SECRET,
		signatureHeader: HEADER,
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

describe("hmac-sha256", () => {
	it("accepts a hex signature by default", () => {
		expect(verify()).toEqual({ ok: true });
	});

	it("accepts a hardcoded reference vector", () => {
		expect(
			verify({
				headers: {
					"x-signature": "9cf00b356e27e349f77b658d7537ec62a6942c4418e9f25f4baf5b256918ae23",
				},
			}),
		).toEqual({ ok: true });
	});

	it("accepts a base64 signature when encoding is base64", () => {
		const headers = { "x-signature": hmacBase64(HMAC_SECRET, BODY) };
		expect(verify({ encoding: "base64", headers })).toEqual({ ok: true });
	});

	it.each(["utf8", "BASE64", "", null])("throws a TypeError for encoding %j", (value) => {
		expect(() => verify({ encoding: value as never })).toThrow(TypeError);
	});

	it("rejects a base64 signature when encoding is hex", () => {
		const headers = { "x-signature": hmacBase64(HMAC_SECRET, BODY) };
		expectCode(() => verify({ headers }), "INVALID_SIGNATURE");
	});

	it("matches the signature header name case-insensitively", () => {
		expect(verify({ signatureHeader: "x-SIGNATURE" })).toEqual({ ok: true });
		expect(
			verify({
				headers: { "X-SIGNATURE": hmacHex(HMAC_SECRET, BODY) },
				signatureHeader: "x-signature",
			}),
		).toEqual({
			ok: true,
		});
	});

	it("accepts any matching value in a comma or whitespace separated rotation list", () => {
		const valid = hmacHex(HMAC_SECRET, BODY);
		expect(verify({ headers: { [HEADER]: `${"0".repeat(64)}, ${valid}` } })).toEqual({ ok: true });
		expect(verify({ headers: { [HEADER]: `${"0".repeat(64)} ${valid}` } })).toEqual({ ok: true });
	});

	it("reads headers from a Headers instance", () => {
		const headers = new Headers({ "x-signature": hmacHex(HMAC_SECRET, BODY) });
		expect(verify({ headers })).toEqual({ ok: true });
	});

	it("throws a TypeError when signatureHeader is not configured", () => {
		expect(() => verify({ signatureHeader: undefined })).toThrow(TypeError);
		expect(() => verify({ signatureHeader: "  " })).toThrow(TypeError);
	});

	it("throws MISSING_HEADER when the signature header is absent", () => {
		expectCode(() => verify({ headers: {} }), "MISSING_HEADER");
	});

	it("throws INVALID_SIGNATURE for a wrong signature", () => {
		expectCode(() => verify({ headers: { [HEADER]: "0".repeat(64) } }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the body was modified", () => {
		expectCode(() => verify({ body: BODY.toUpperCase() }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the raw body is replaced by a re-serialized body", () => {
		const raw = '{ "id":   "evt_1" }';
		const headers = { [HEADER]: hmacHex(HMAC_SECRET, raw) };
		expect(verify({ body: raw, headers }).ok).toBe(true);
		expectCode(
			() => verify({ body: JSON.stringify(JSON.parse(raw)), headers }),
			"INVALID_SIGNATURE",
		);
	});

	it("never reports a timestamp and ignores the tolerance", () => {
		expect(verify({ toleranceSeconds: 0, now: () => 0 })).toEqual({ ok: true });
	});

	it("throws MALFORMED_SECRET for an empty secret", () => {
		expectCode(() => verify({ secret: "" }), "MALFORMED_SECRET");
	});
});
