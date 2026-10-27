import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookSignatureError } from "../src/index";
import { BODY, GITHUB_SECRET, getError, hmacHex, NOW_MS, signGithub } from "./helpers";

const validHeaders = { "x-hub-signature-256": signGithub(GITHUB_SECRET, BODY) };

function baseOptions() {
	return {
		scheme: "github" as const,
		body: BODY,
		headers: validHeaders,
		secret: GITHUB_SECRET,
		now: () => NOW_MS,
	};
}

describe("verifyWebhook options and dispatch", () => {
	it("accepts provider as an alias of scheme", () => {
		const { scheme: _scheme, ...rest } = baseOptions();
		expect(verifyWebhook({ ...rest, provider: "github" })).toEqual({ ok: true });
	});

	it("accepts scheme and provider when they agree", () => {
		expect(verifyWebhook({ ...baseOptions(), provider: "github" })).toEqual({ ok: true });
	});

	it("throws a TypeError when scheme and provider conflict", () => {
		expect(() => verifyWebhook({ ...baseOptions(), provider: "stripe" })).toThrow(TypeError);
	});

	it.each([
		["unknown name", { scheme: "paypal" }],
		["neither scheme nor provider", {}],
	])("throws UNSUPPORTED_SCHEME for %s", (_label, override) => {
		const { scheme: _scheme, ...rest } = baseOptions();
		const error = getError(() => verifyWebhook({ ...rest, ...(override as object) } as never));
		expect(error).toBeInstanceOf(WebhookSignatureError);
		expect((error as WebhookSignatureError).code).toBe("UNSUPPORTED_SCHEME");
	});

	it("throws a WebhookSignatureError that is also an Error with a stable name", () => {
		const error = getError(() => verifyWebhook({ ...baseOptions(), headers: {} }));
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(WebhookSignatureError);
		expect((error as Error).name).toBe("WebhookSignatureError");
		expect((error as WebhookSignatureError).code).toBe("MISSING_HEADER");
	});

	it("accepts a Uint8Array body with the same bytes as the string", () => {
		const bytes = new TextEncoder().encode(BODY);
		expect(verifyWebhook({ ...baseOptions(), body: bytes })).toEqual({ ok: true });
	});

	it("treats a string body as UTF-8", () => {
		const body = '{"name":"Müller ✓"}';
		const headers = { "x-hub-signature-256": signGithub(GITHUB_SECRET, body) };
		expect(verifyWebhook({ ...baseOptions(), body, headers })).toEqual({ ok: true });
		expect(
			verifyWebhook({ ...baseOptions(), body: new TextEncoder().encode(body), headers }),
		).toEqual({ ok: true });
	});

	it("rejects a body that is neither string nor Uint8Array", () => {
		expect(() => verifyWebhook({ ...baseOptions(), body: { id: 1 } as never })).toThrow(TypeError);
	});

	it("rejects missing headers", () => {
		expect(() => verifyWebhook({ ...baseOptions(), headers: undefined as never })).toThrow(
			TypeError,
		);
	});

	it("rejects a non-finite now()", () => {
		expect(() => verifyWebhook({ ...baseOptions(), now: () => Number.NaN })).toThrow(TypeError);
	});

	it.each([-1, Number.NaN, "300" as unknown as number])(
		"rejects invalid toleranceSeconds %s",
		(value) => {
			expect(() => verifyWebhook({ ...baseOptions(), toleranceSeconds: value })).toThrow(TypeError);
		},
	);

	it("reads headers case-insensitively from a plain record", () => {
		const headers = { "X-Hub-Signature-256": signGithub(GITHUB_SECRET, BODY) };
		expect(verifyWebhook({ ...baseOptions(), headers })).toEqual({ ok: true });
	});

	it("joins repeated header values (Node req.headers arrays) with a comma", () => {
		const headers = { "x-signature": [hmacHex(GITHUB_SECRET, BODY), "0".repeat(64)] };
		expect(
			verifyWebhook({
				scheme: "hmac-sha256",
				body: BODY,
				headers,
				secret: GITHUB_SECRET,
				signatureHeader: "x-signature",
			}),
		).toEqual({ ok: true });
	});

	it("ignores undefined header values and prefers the first defined value of duplicate keys", () => {
		const headers = {
			"X-Hub-Signature-256": undefined,
			"x-hub-signature-256": signGithub(GITHUB_SECRET, BODY),
		};
		expect(verifyWebhook({ ...baseOptions(), headers })).toEqual({ ok: true });
	});

	it("never includes the secret in error messages", () => {
		const secret = "super-secret-value-do-not-leak";
		const error = getError(() =>
			verifyWebhook({ ...baseOptions(), secret, headers: { "x-hub-signature-256": "sha256=00" } }),
		);
		expect(error).toBeInstanceOf(WebhookSignatureError);
		expect((error as Error).message).not.toContain(secret);
	});
});
