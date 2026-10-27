export type WebhookErrorCode =
	| "MISSING_HEADER"
	| "INVALID_SIGNATURE"
	| "TIMESTAMP_OUT_OF_TOLERANCE"
	| "MALFORMED_SECRET"
	| "UNSUPPORTED_SCHEME";

/**
 * Thrown by `verifyWebhook` when a request cannot be verified.
 * Messages never contain the secret or the signature material.
 */
export class WebhookSignatureError extends Error {
	readonly code: WebhookErrorCode;

	constructor(code: WebhookErrorCode, message: string) {
		super(message);
		this.name = "WebhookSignatureError";
		this.code = code;
	}
}
