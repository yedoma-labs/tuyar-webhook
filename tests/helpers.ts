import { createHmac } from "node:crypto";

/** Fixed reference time used by all tests (ms). */
export const NOW_MS = 1_700_000_000_000;
export const NOW_SECONDS = 1_700_000_000;
export const BODY = '{"id":"evt_1","type":"ping"}';

/** Independent signing helpers, written with node:crypto directly and not using the library code. */
export function hmacHex(key: string | Buffer, data: string): string {
	return createHmac("sha256", key).update(data).digest("hex");
}

export function hmacBase64(key: string | Buffer, data: string): string {
	return createHmac("sha256", key).update(data).digest("base64");
}

export function signStandard(secret: string, id: string, timestamp: number, body: string): string {
	const key = Buffer.from(secret.slice("whsec_".length), "base64");
	return `v1,${hmacBase64(key, `${id}.${timestamp}.${body}`)}`;
}

export function signStripe(secret: string, timestamp: number, body: string): string {
	return `t=${timestamp},v1=${hmacHex(secret, `${timestamp}.${body}`)}`;
}

export function signGithub(secret: string, body: string): string {
	return `sha256=${hmacHex(secret, body)}`;
}

export const STANDARD_SECRET = "whsec_c3RhbmRhcmQta2V5LWJ5dGVzLTAxMjM0NTY3ODk=";
export const STANDARD_KEY = Buffer.from("standard-key-bytes-0123456789");
export const STRIPE_SECRET = "whsec_test_secret_123";
export const GITHUB_SECRET = "github-test-secret";
export const HMAC_SECRET = "generic-secret";

/** Returns the thrown value, failing the test when nothing is thrown. */
export function getError(fn: () => unknown): unknown {
	try {
		fn();
	} catch (error) {
		return error;
	}
	throw new Error("expected a throw");
}
