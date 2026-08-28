const dns = require("node:dns");
const fs = require("node:fs");
const path = require("node:path");
const ipaddr = require("ipaddr.js");
const undici = require("undici");
const Log = require("logger");

const startUp = new Date();






function getStartup (req, res) {
	res.send(startUp);
}






function replaceSecretPlaceholder (input) {
	if (global.config.cors !== "allowAll") {
		return input.replaceAll(/\*\*(SECRET_[^*]+)\*\*/g, (match, group) => {
			return process.env[group];
		});
	} else {
		if (input.includes("**SECRET_")) {
			Log.error("Replacing secrets doesn't work with CORS `allowAll`, you need to set `cors` to `disabled` or `allowWhitelist` in `config.js`");
		}
		return input;
	}
}











async function cors (req, res) {
	if (global.config.cors === "disabled") {
		Log.error("CORS is disabled, you need to enable it in `config.js` by setting `cors` to `allowAll` or `allowWhitelist`");
		return res.status(403).json({ error: "CORS proxy is disabled" });
	}
	let url;
	try {
		const urlRegEx = "url=(.+?)$";

		const match = new RegExp(urlRegEx, "g").exec(req.url);
		if (!match) {
			url = `invalid url: ${req.url}`;
			Log.error(url);
			return res.status(400).send(url);
		} else {
			url = match[1];
			if (typeof global.config !== "undefined") {
				if (config.hideConfigSecrets) {
					url = replaceSecretPlaceholder(url);
				}
			}


			let parsed;
			try {
				parsed = new URL(url);
			} catch {
				Log.warn(`SSRF blocked (invalid URL): ${url}`);
				return res.status(403).json({ error: "Forbidden: private or reserved addresses are not allowed" });
			}
			if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
				Log.warn(`SSRF blocked (protocol): ${url}`);
				return res.status(403).json({ error: "Forbidden: private or reserved addresses are not allowed" });
			}


			if (parsed.hostname.toLowerCase() === "localhost") {
				Log.warn(`SSRF blocked (localhost): ${url}`);
				return res.status(403).json({ error: "Forbidden: private or reserved addresses are not allowed" });
			}


			if (global.config.cors === "allowWhitelist" && !global.config.corsDomainWhitelist.includes(parsed.hostname.toLowerCase())) {
				Log.warn(`CORS blocked (not in whitelist): ${url}`);
				return res.status(403).json({ error: "Forbidden: domain not in corsDomainWhitelist" });
			}

			const headersToSend = getHeadersToSend(req.url);
			const expectedReceivedHeaders = geExpectedReceivedHeaders(req.url);
			Log.log(`cors url: ${url}`);




			const { address, family } = await dns.promises.lookup(parsed.hostname);
			if (ipaddr.process(address).range() !== "unicast") {
				Log.warn(`SSRF blocked: ${url}`);
				return res.status(403).json({ error: "Forbidden: private or reserved addresses are not allowed" });
			}


			const dispatcher = new undici.Agent({
				connect: {
					lookup: (_h, _o, cb) => {
						const addresses = [{ address: address, family: family }];
						process.nextTick(() => cb(null, addresses));
					}
				}
			});

			const response = await undici.fetch(url, { dispatcher, headers: headersToSend });
			if (response.ok) {
				for (const header of expectedReceivedHeaders) {
					const headerValue = response.headers.get(header);
					if (header) res.set(header, headerValue);
				}
				const arrayBuffer = await response.arrayBuffer();
				res.send(Buffer.from(arrayBuffer));
			} else {
				throw new Error(`Response status: ${response.status}`);
			}
		}
	} catch (error) {
		if (process.env.mmTestMode !== "true") {
			Log.error(`Error in CORS request: ${error}`);
		}
		res.status(500).json({ error: error.message });
	}
}






function getHeadersToSend (url) {
	const headersToSend = { "User-Agent": getUserAgent() };
	const headersToSendMatch = new RegExp("sendheaders=(.+?)(&|$)", "g").exec(url);
	if (headersToSendMatch) {
		const headers = headersToSendMatch[1].split(",");
		for (const header of headers) {
			const keyValue = header.split(":");
			if (keyValue.length !== 2) {
				throw new Error(`Invalid format for header ${header}`);
			}
			headersToSend[keyValue[0]] = decodeURIComponent(keyValue[1]);
		}
	}
	return headersToSend;
}






function geExpectedReceivedHeaders (url) {
	const expectedReceivedHeaders = ["Content-Type"];
	const expectedReceivedHeadersMatch = new RegExp("expectedheaders=(.+?)(&|$)", "g").exec(url);
	if (expectedReceivedHeadersMatch) {
		const headers = expectedReceivedHeadersMatch[1].split(",");
		for (const header of headers) {
			expectedReceivedHeaders.push(header);
		}
	}
	return expectedReceivedHeaders;
}






function getHtml (req, res) {
	let html = fs.readFileSync(path.resolve(`${global.root_path}/index.html`), { encoding: "utf8" });
	html = html.replace("#VERSION#", global.version);
	html = html.replace("#TESTMODE#", global.mmTestMode);

	res.send(html);
}






function getVersion (req, res) {
	res.send(global.version);
}





function getUserAgent () {
	const defaultUserAgent = `Mozilla/5.0 (Node.js ${Number(process.version.match(/^v(\d+\.\d+)/)[1])}) MagicMirror/${global.version}`;

	if (typeof global.config === "undefined") {
		return defaultUserAgent;
	}

	switch (typeof global.config.userAgent) {
		case "function":
			return global.config.userAgent();
		case "string":
			return global.config.userAgent;
		default:
			return defaultUserAgent;
	}
}





function getEnvVarsAsObj () {
	const obj = { modulesDir: `${global.config.foreignModulesDir}`, defaultModulesDir: `${global.config.defaultModulesDir}`, customCss: `${global.config.customCss}` };
	if (process.env.MM_MODULES_DIR) {
		obj.modulesDir = process.env.MM_MODULES_DIR.replace(`${global.root_path}/`, "");
	}
	if (process.env.MM_CUSTOMCSS_FILE) {
		obj.customCss = process.env.MM_CUSTOMCSS_FILE.replace(`${global.root_path}/`, "");
	}

	return obj;
}






function getEnvVars (req, res) {
	const obj = getEnvVarsAsObj();
	res.send(obj);
}





function getConfigFilePath () {

	if (!global.root_path) {
		global.root_path = path.resolve(`${__dirname}/../`);
	}


	if (!global.configuration_file && process.env.MM_CONFIG_FILE) {
		global.configuration_file = process.env.MM_CONFIG_FILE;
	}

	return path.resolve(global.configuration_file || `${global.root_path}/config/config.js`);
}

module.exports = { cors, getHtml, getVersion, getStartup, getEnvVars, getEnvVarsAsObj, getUserAgent, getConfigFilePath, replaceSecretPlaceholder };
