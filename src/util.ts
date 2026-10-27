import { createHmac, timingSafeEqual } from "node:crypto";
import { WebhookSignatureError } from "./errors";
import type { HeadersInput } from "./types";

export type HeaderMap = ReadonlyMap<string, string>;

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})+$/;
const DIGITS_PATTERN = /^\d+$/;

/** Copies headers into a map keyed by lowercase name. Undefined values are skipped. */
export function normalizeHeaders(input: HeadersInput): HeaderMap {
	const map = new Map<string, string>();
	if (typeof (input as Headers).get === "function") {
		(input as Headers).forEach((value, name) => {
			map.set(name.toLowerCase(), value);
		});
		return map;
	}
	for (const [name, value] of Object.entries(input)) {
		const joined = Array.isArray(value) ? value.join(", ") : value;
		if (typeof joined !== "string") continue;
		const key = name.toLowerCase();
		if (!map.has(key)) map.set(key, joined);
	}
	return map;
}

/** Returns the trimmed header value, or undefined when absent or empty. */
export function readHeader(headers: HeaderMap, name: string): string | undefined {
	const value = headers.get(name.toLowerCase())?.trim();
	return value === undefined || value === "" ? undefined : value;
}

export function requireHeader(headers: HeaderMap, name: string): string {
	const value = readHeader(headers, name);
	if (value === undefined) {
		throw new WebhookSignatureError("MISSING_HEADER", `Missing required header: ${name}`);
	}
	return value;
}

export function toBytes(data: string | Uint8Array): Uint8Array {
	return typeof data === "string" ? Buffer.from(data, "utf8") : data;
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Buffer {
	return createHmac("sha256", key).update(data).digest();
}

/** Constant-time comparison. Lengths are compared first, which only reveals the length. */
export function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
	return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}

/** Checks every candidate (no early exit) so the work does not depend on which one matched. */
export function matchesAny(
	expected: Uint8Array,
	candidates: readonly (Uint8Array | undefined)[],
): boolean {
	let matched = false;
	for (const candidate of candidates) {
		if (candidate !== undefined && safeEqual(expected, candidate)) matched = true;
	}
	return matched;
}

export function decodeHex(value: string): Buffer | undefined {
	if (!HEX_PATTERN.test(value)) return undefined;
	return Buffer.from(value, "hex");
}

/** Decodes canonical padded base64 only. Returns undefined for anything else. */
export function decodeBase64(value: string): Buffer | undefined {
	if (!BASE64_PATTERN.test(value)) return undefined;
	const decoded = Buffer.from(value, "base64");
	return decoded.toString("base64") === value ? decoded : undefined;
}

export function parseUnixSeconds(value: string): number | undefined {
	if (!DIGITS_PATTERN.test(value)) return undefined;
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) ? parsed : undefined;
}
