import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookSignatureError } from "../src/index";
import { BODY, getError, NOW_MS, NOW_SECONDS, STANDARD_SECRET, signStandard } from "./helpers";

const ID = "msg_42";

function headersFor(
	body: string,
	overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
	return {
		"webhook-id": ID,
		"webhook-timestamp": String(NOW_SECONDS),
		"webhook-signature": signStandard(STANDARD_SECRET, ID, NOW_SECONDS, body),
		...overrides,
	};
}

function verify(
	overrides: Partial<Parameters<typeof verifyWebhook>[0]> & {
		headers?: Record<string, string | undefined>;
	} = {},
) {
	return verifyWebhook({
		scheme: "standard-webhooks",
		body: BODY,
		headers: headersFor(BODY),
		secret: STANDARD_SECRET,
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

describe("standard-webhooks", () => {
	it("accepts a valid signature and returns the timestamp", () => {
		expect(verify()).toEqual({ ok: true, timestamp: NOW_SECONDS });
	});

	it("accepts a hardcoded reference vector", () => {
		const body = '{"id":"evt_1","type":"ping"}';
		const result = verifyWebhook({
			scheme: "standard-webhooks",
			body,
			headers: {
				"webhook-id": "msg_42",
				"webhook-timestamp": "1700000000",
				"webhook-signature": "v1,toXqaGm/hJkxpNpWAOYsZ1JlRqyZUYaj1zscIZpMSms=",
			},
			secret: STANDARD_SECRET,
			now: () => NOW_MS,
		});
		expect(result).toEqual({ ok: true, timestamp: NOW_SECONDS });
	});

	it("accepts a Uint8Array body with the same bytes", () => {
		expect(verify({ body: new TextEncoder().encode(BODY) })).toEqual({
			ok: true,
			timestamp: NOW_SECONDS,
		});
	});

	it("accepts any matching signature in a rotated list", () => {
		const valid = signStandard(STANDARD_SECRET, ID, NOW_SECONDS, BODY);
		const headers = headersFor(BODY, {
			"webhook-signature": `v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ${valid}`,
		});
		expect(verify({ headers }).ok).toBe(true);
	});

	it("ignores signatures with unknown versions", () => {
		const valid = signStandard(STANDARD_SECRET, ID, NOW_SECONDS, BODY).replace("v1,", "v2,");
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-signature": valid }) }),
			"INVALID_SIGNATURE",
		);
	});

	it.each(["webhook-id", "webhook-timestamp", "webhook-signature"])(
		"throws MISSING_HEADER when %s is absent",
		(name) => {
			expectCode(
				() => verify({ headers: headersFor(BODY, { [name]: undefined }) }),
				"MISSING_HEADER",
			);
		},
	);

	it("throws MISSING_HEADER when a header is empty", () => {
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-id": "  " }) }),
			"MISSING_HEADER",
		);
	});

	it("throws INVALID_SIGNATURE for a wrong signature", () => {
		const headers = headersFor(BODY, {
			"webhook-signature": "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		});
		expectCode(() => verify({ headers }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the body was modified", () => {
		expectCode(() => verify({ body: BODY.replace("ping", "pong") }), "INVALID_SIGNATURE");
	});

	it("throws INVALID_SIGNATURE when the message id was modified", () => {
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-id": "msg_43" }) }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws INVALID_SIGNATURE when the raw body is replaced by a re-serialized one", () => {
		const raw = '{ "id": "evt_1", "type": "ping" }';
		const headers = headersFor(raw);
		const reserialized = JSON.stringify(JSON.parse(raw));
		expectCode(() => verify({ body: reserialized, headers }), "INVALID_SIGNATURE");
		expect(verify({ body: raw, headers })).toEqual({ ok: true, timestamp: NOW_SECONDS });
	});

	it("throws INVALID_SIGNATURE for a non-numeric timestamp", () => {
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-timestamp": "abc" }) }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws MISSING_HEADER for an empty signature and INVALID_SIGNATURE without a v1 entry", () => {
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-signature": "" }) }),
			"MISSING_HEADER",
		);
		expectCode(
			() => verify({ headers: headersFor(BODY, { "webhook-signature": "v1" }) }),
			"INVALID_SIGNATURE",
		);
	});

	it("throws TIMESTAMP_OUT_OF_TOLERANCE for an expired timestamp", () => {
		const old = NOW_SECONDS - 301;
		const headers = headersFor(BODY, {
			"webhook-timestamp": String(old),
			"webhook-signature": signStandard(STANDARD_SECRET, ID, old, BODY),
		});
		expectCode(() => verify({ headers }), "TIMESTAMP_OUT_OF_TOLERANCE");
	});

	it("accepts a timestamp exactly at the tolerance boundary", () => {
		const old = NOW_SECONDS - 300;
		const headers = headersFor(BODY, {
			"webhook-timestamp": String(old),
			"webhook-signature": signStandard(STANDARD_SECRET, ID, old, BODY),
		});
		expect(verify({ headers }).ok).toBe(true);
	});

	it("throws TIMESTAMP_OUT_OF_TOLERANCE for a timestamp in the future", () => {
		const future = NOW_SECONDS + 301;
		const headers = headersFor(BODY, {
			"webhook-timestamp": String(future),
			"webhook-signature": signStandard(STANDARD_SECRET, ID, future, BODY),
		});
		expectCode(() => verify({ headers }), "TIMESTAMP_OUT_OF_TOLERANCE");
	});

	it("respects a custom toleranceSeconds", () => {
		expectCode(
			() => verify({ toleranceSeconds: 10, now: () => NOW_MS + 11_000 }),
			"TIMESTAMP_OUT_OF_TOLERANCE",
		);
		expect(verify({ toleranceSeconds: 10, now: () => NOW_MS + 10_000 }).ok).toBe(true);
	});

	it("uses Date.now by default", () => {
		const realNow = Date.now;
		Date.now = () => NOW_MS;
		try {
			expect(
				verifyWebhook({
					scheme: "standard-webhooks",
					body: BODY,
					headers: headersFor(BODY),
					secret: STANDARD_SECRET,
				}).ok,
			).toBe(true);
		} finally {
			Date.now = realNow;
		}
	});

	it.each([
		["missing prefix", "c3RhbmRhcmQta2V5LWJ5dGVzLTAxMjM0NTY3ODk="],
		["invalid base64", "whsec_not base64!"],
		["empty key", "whsec_"],
		["non-canonical base64", "whsec_c3RhbmRhcmQ"],
	])("throws MALFORMED_SECRET for %s", (_label, secret) => {
		expectCode(() => verify({ secret }), "MALFORMED_SECRET");
	});

	it("throws MALFORMED_SECRET for a Uint8Array secret", () => {
		expectCode(() => verify({ secret: new Uint8Array([1, 2, 3]) }), "MALFORMED_SECRET");
	});

	it("does not leak the secret in error messages", () => {
		const invalid = getError(() => verify({ secret: "whsec_not base64!" })) as Error;
		expect(invalid.message).not.toContain("not base64");
		const forged = getError(() =>
			verify({ headers: headersFor(BODY, { "webhook-signature": "v1,AAAA" }) }),
		) as Error;
		expect(forged.message).not.toContain(STANDARD_SECRET);
	});
});
