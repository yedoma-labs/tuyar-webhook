/** Signature schemes supported by `verifyWebhook`. */
export type WebhookScheme = "standard-webhooks" | "stripe" | "github" | "hmac-sha256";

/**
 * Request headers, either as a fetch `Headers` instance or a plain record such as
 * Node's `req.headers`. Header names are matched case-insensitively. Array values
 * (repeated headers) are joined with ", ".
 */
export type HeadersInput = Headers | Record<string, string | readonly string[] | undefined>;

/** Successful verification result. `timestamp` is Unix time in seconds, if the scheme carries one. */
export interface VerifyResult {
	readonly ok: true;
	readonly timestamp?: number;
}

export interface VerifyWebhookOptions {
	/** Signature scheme to verify. Either `scheme` or `provider` must be set. */
	readonly scheme?: WebhookScheme;
	/** Alias of `scheme`. */
	readonly provider?: WebhookScheme;
	/**
	 * The RAW request body exactly as it was received. A string is hashed as UTF-8.
	 * Do not pass a parsed or re-serialized body: any change breaks the signature.
	 */
	readonly body: string | Uint8Array;
	readonly headers: HeadersInput;
	/**
	 * Shared secret. `standard-webhooks` expects `whsec_<base64>`.
	 * Stripe and GitHub secrets are used as UTF-8 bytes.
	 */
	readonly secret: string | Uint8Array;
	/** Maximum allowed clock skew between the signed timestamp and `now()`, in seconds. Default: 300. */
	readonly toleranceSeconds?: number;
	/** Returns the current time in milliseconds. Default: `Date.now`. */
	readonly now?: () => number;
	/** Header carrying the signature. Required for `hmac-sha256`. */
	readonly signatureHeader?: string;
	/** Encoding of the `hmac-sha256` signature. Default: `"hex"`. */
	readonly encoding?: "hex" | "base64";
}
