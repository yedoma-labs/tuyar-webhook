import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookSignatureError } from "../src/index";
import { BODY, GITHUB_SECRET, hmacHex, NOW_MS, signGithub } from "./helpers";

function verify(
	overrides: Partial<Parameters<typeof verifyWebhook>[0]> & {
		headers?: Record<string, string | undefined>;
	} = {},
) {
	return verifyWebhook({
		scheme: "github",
		body: BODY,
		headers: { "x-hub-signature-256": signGithub(GITHUB_SECRET, BODY) },
		secret: GITHUB_SECRET,
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

describe("github", () => {
	it("accepts a valid signature without returning a timestamp", () => {
		const result = verify();
		expect(result).toEqual({ ok: true });
		expect(result).not.toHaveProperty("timestamp");
	});

	it("accepts a hardcoded reference vector", () => {
		const result = verifyWebhook({
			scheme: "github",
			body: BODY,
			headers: {
				"x-hub-signature-256":
					"sha256=038ef407a3cfc8e23c095216cbf5733ae30461216c3c9b0a4a2bec0a5159f6b3",
			},
			secret: GITHUB_SECRET,
		});
		expect(result).toEqual({ ok: true });
	});

	it("accepts a Uint8Array secret and an uppercase hex digest", () => {
		const upper = `sha256=${hmacHex(GITHUB_SECRET, BODY).toUpperCase()}`;
		expect(
			verify({
				secret: new TextEncoder().encode(GITHUB_SECRET),
				headers: { "x-hub-signature-256": upper },
			}),
		).toEqual({ ok: true });
	});

	it("reads the header case-insensitively", () => {
		const headers = new Headers({ "X-Hub-Signature-256": signGithub(GITHUB_SECRET, BODY) });
		expect(verify({ headers })).toEqual({ ok: true });
	});

	it("does not apply a timestamp tolerance", () => {
		expect(verify({ toleranceSeconds: 0, now: () => 0 })).toEqual({ ok: true });
	});

	it("throws MISSING_HEADER when x-hub-signature-256 is absent", () => {
		expectCode(() => verify({ headers: {} }), "MISSING_HEADER");
	});

	it("throws INVALID_SIGNATURE for a sha1 prefix or missing prefix", () => {
		const digest = hmacHex(GITHUB_SECRET, BODY);
		expectCode(
			() => verify({ headers: { "x-hub-signature-256": `sha1=${digest}` } }),
			"INVALID_SIGNATURE",
		);
		expectCode(() => verify({ headers: { "x-hub-signature-256": digest } }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE for a wrong or malformed digest", () => {
		expectCode(
			() => verify({ headers: { "x-hub-signature-256": `sha256=${"0".repeat(64)}` } }),
			"INVALID_SIGNATURE",
		);
		expectCode(
			() => verify({ headers: { "x-hub-signature-256": "sha256=xyz" } }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE when the body was modified", () => {
		expectCode(() => verify({ body: `${BODY} ` }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the raw body is replaced by a re-serialized body", () => {
		const raw = '{ "id": "evt_1", "type": "ping" }';
		const headers = { "x-hub-signature-256": signGithub(GITHUB_SECRET, raw) };
		expect(verify({ body: raw, headers }).ok).toBe(true);
		expectCode(
			() => verify({ body: JSON.stringify(JSON.parse(raw)), headers }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws MALFORMED_SECRET for an empty secret", () => {
		expectCode(() => verify({ secret: "" }), "MALFORMED_SECRET");
	});
});
