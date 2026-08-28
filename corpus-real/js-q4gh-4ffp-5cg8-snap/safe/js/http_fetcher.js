const { EventEmitter } = require("node:events");
const { fetch: undiciFetch, Agent } = require("undici");
const Log = require("logger");
const { getUserAgent } = require("#server_functions");

const FIFTEEN_MINUTES = 15 * 60 * 1000;
const THIRTY_MINUTES = 30 * 60 * 1000;
const MAX_SERVER_BACKOFF = 3;
const DEFAULT_TIMEOUT = 30000;






const ERROR_TYPE_TO_TRANSLATION = {
	AUTH_FAILURE: "MODULE_ERROR_UNAUTHORIZED",
	RATE_LIMITED: "MODULE_ERROR_RATE_LIMITED",
	SERVER_ERROR: "MODULE_ERROR_SERVER_ERROR",
	CLIENT_ERROR: "MODULE_ERROR_CLIENT_ERROR",
	NETWORK_ERROR: "MODULE_ERROR_NO_CONNECTION",
	UNKNOWN_ERROR: "MODULE_ERROR_UNSPECIFIED"
};



















class HTTPFetcher extends EventEmitter {














	static calculateBackoffDelay (attempt, { baseDelay = 15000, maxDelay = 300000 } = {}) {
		return Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
	}
















	constructor (url, options = {}) {
		super();

		this.url = url;
		this.reloadInterval = options.reloadInterval || 5 * 60 * 1000;
		this.auth = options.auth || null;
		this.selfSignedCert = options.selfSignedCert || false;
		this.customHeaders = options.headers || {};
		this.maxRetries = options.maxRetries || MAX_SERVER_BACKOFF;
		this.timeout = options.timeout || DEFAULT_TIMEOUT;
		this.logContext = options.logContext ? `[${options.logContext}] ` : "";

		this.reloadTimer = null;
		this.serverErrorCount = 0;
		this.networkErrorCount = 0;
	}




	clearTimer () {
		if (this.reloadTimer) {
			clearTimeout(this.reloadTimer);
			this.reloadTimer = null;
		}
	}








	scheduleNextFetch (delay) {
		let nextDelay = delay ?? this.reloadInterval;



		if (nextDelay < 1000) {
			nextDelay = this.reloadInterval;
		}


		if (process.env.mmTestMode === "true") {
			return;
		}

		this.reloadTimer = setTimeout(() => this.fetch(), nextDelay);
	}




	startPeriodicFetch () {
		this.fetch();
	}





	getRequestOptions () {
		const headers = {
			"User-Agent": getUserAgent(),
			...this.customHeaders
		};
		const options = { headers };

		if (this.selfSignedCert) {
			options.dispatcher = new Agent({
				connect: {
					rejectUnauthorized: false
				}
			});
		}

		if (this.auth) {
			if (this.auth.method === "bearer") {
				headers.Authorization = `Bearer ${this.auth.pass}`;
			} else {
				headers.Authorization = `Basic ${Buffer.from(`${this.auth.user}:${this.auth.pass}`).toString("base64")}`;
			}
		}

		return options;
	}






	#parseRetryAfter (retryAfter) {

		const seconds = Number(retryAfter);
		if (!Number.isNaN(seconds) && seconds >= 0) {
			return seconds * 1000;
		}


		const retryDate = Date.parse(retryAfter);
		if (!Number.isNaN(retryDate)) {
			return Math.max(0, retryDate - Date.now());
		}

		return null;
	}





	#shortenUrl () {
		try {
			const urlObj = new URL(this.url);
			return `${urlObj.origin}${urlObj.pathname}${urlObj.search.length > 50 ? "?..." : urlObj.search}`;
		} catch {
			return this.url;
		}
	}






	#getDelayForResponse (response) {
		const { status } = response;
		let delay = this.reloadInterval;
		let message;
		let errorType = "UNKNOWN_ERROR";

		if (status === 401 || status === 403) {
			errorType = "AUTH_FAILURE";
			delay = Math.max(this.reloadInterval * 5, THIRTY_MINUTES);
			message = `Authentication failed (${status}). Check your API key. Waiting ${Math.round(delay / 60000)} minutes before retry.`;
			Log.error(`${this.logContext}${this.#shortenUrl()} - ${message}`);
		} else if (status === 429) {
			errorType = "RATE_LIMITED";
			const retryAfter = response.headers.get("retry-after");
			const parsed = retryAfter ? this.#parseRetryAfter(retryAfter) : null;
			delay = parsed !== null ? Math.max(parsed, this.reloadInterval) : Math.max(this.reloadInterval * 2, FIFTEEN_MINUTES);
			message = `Rate limited (429). Retrying in ${Math.round(delay / 60000)} minutes.`;
			Log.warn(`${this.logContext}${this.#shortenUrl()} - ${message}`);
		} else if (status >= 500) {
			errorType = "SERVER_ERROR";
			this.serverErrorCount = Math.min(this.serverErrorCount + 1, this.maxRetries);
			if (this.serverErrorCount >= this.maxRetries) {
				delay = this.reloadInterval;
				message = `Server error (${status}). Max retries reached, retrying at configured interval (${Math.round(delay / 1000)}s).`;
			} else {
				delay = HTTPFetcher.calculateBackoffDelay(this.serverErrorCount, {
					maxDelay: this.reloadInterval
				});
				message = `Server error (${status}). Retry #${this.serverErrorCount} in ${Math.round(delay / 1000)}s.`;
			}
			Log.error(`${this.logContext}${this.#shortenUrl()} - ${message}`);
		} else if (status >= 400) {
			errorType = "CLIENT_ERROR";
			delay = Math.max(this.reloadInterval * 2, FIFTEEN_MINUTES);
			message = `Client error (${status}). Retrying in ${Math.round(delay / 60000)} minutes.`;
			Log.error(`${this.logContext}${this.#shortenUrl()} - ${message}`);
		} else {
			message = `Unexpected HTTP status ${status}.`;
			Log.error(`${this.logContext}${this.#shortenUrl()} - ${message}`);
		}

		return {
			delay,
			errorInfo: this.#createErrorInfo(message, status, errorType, delay)
		};
	}










	#createErrorInfo (message, status, errorType, retryAfter, originalError = null) {
		return {
			message,
			status,
			errorType,
			translationKey: ERROR_TYPE_TO_TRANSLATION[errorType] || "MODULE_ERROR_UNSPECIFIED",
			retryAfter,
			retryCount: errorType === "NETWORK_ERROR" ? this.networkErrorCount : this.serverErrorCount,
			url: this.url,
			originalError
		};
	}






	async fetch () {
		this.clearTimer();

		let nextDelay = this.reloadInterval;
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), this.timeout);

		try {
			const requestOptions = this.getRequestOptions();



			const fetchFn = requestOptions.dispatcher ? undiciFetch : globalThis.fetch;
			const response = await fetchFn(this.url, {
				...requestOptions,
				signal: controller.signal
			});

			const isSuccessfulResponse = response.ok || response.status === 304;

			if (isSuccessfulResponse) {

				this.serverErrorCount = 0;
				this.networkErrorCount = 0;






				this.emit("response", response);
			} else {
				const { delay, errorInfo } = this.#getDelayForResponse(response);
				nextDelay = delay;
				this.emit("error", errorInfo);
			}
		} catch (error) {
			const isTimeout = error.name === "AbortError";
			const message = isTimeout ? `Request timeout after ${this.timeout}ms` : `Network error: ${error.message}`;

			this.networkErrorCount = Math.min(this.networkErrorCount + 1, this.maxRetries);
			const exhausted = this.networkErrorCount >= this.maxRetries;

			if (exhausted) {
				nextDelay = this.reloadInterval;
				Log.error(`${this.logContext}${this.#shortenUrl()} - ${message} Max retries reached, retrying at configured interval (${Math.round(nextDelay / 1000)}s).`);
			} else {
				nextDelay = HTTPFetcher.calculateBackoffDelay(this.networkErrorCount, {
					maxDelay: this.reloadInterval
				});
				const retryMsg = `${this.logContext}${this.#shortenUrl()} - ${message} Retry #${this.networkErrorCount} in ${Math.round(nextDelay / 1000)}s.`;
				if (this.networkErrorCount <= 2) {
					Log.warn(retryMsg);
				} else {
					Log.error(retryMsg);
				}
			}

			const errorInfo = this.#createErrorInfo(
				message,
				null,
				"NETWORK_ERROR",
				nextDelay,
				error
			);
			this.emit("error", errorInfo);
		} finally {
			clearTimeout(timeoutId);
		}

		this.scheduleNextFetch(nextDelay);
	}
}

module.exports = HTTPFetcher;
