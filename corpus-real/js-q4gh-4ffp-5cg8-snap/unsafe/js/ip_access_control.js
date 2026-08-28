const ipaddr = require("ipaddr.js");
const Log = require("logger");







function isAllowed (clientIp, whitelist) {
	try {
		const addr = ipaddr.process(clientIp);

		return whitelist.some((entry) => {
			try {

				if (entry.includes("/")) {
					const [rangeAddr, prefixLen] = ipaddr.parseCIDR(entry);
					return addr.match(rangeAddr, prefixLen);
				}


				const allowedAddr = ipaddr.process(entry);
				return addr.toString() === allowedAddr.toString();
			} catch {
				Log.warn(`Invalid whitelist entry: ${entry}`);
				return false;
			}
		});
	} catch {
		Log.warn(`Failed to parse client IP: ${clientIp}`);
		return false;
	}
}








function resolveClientIp (req) {
	const directIp = req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip;
	const LOOPBACK_WHITELIST = ["127.0.0.1", "::ffff:127.0.0.1", "::1"];

	if (isAllowed(directIp, LOOPBACK_WHITELIST)) {
		const forwardedFor = req.headers?.["x-forwarded-for"];
		if (typeof forwardedFor === "string" && forwardedFor.trim().length > 0) {
			return forwardedFor.split(",")[0].trim();
		}
	}

	return directIp;
}






function ipAccessControl (whitelist) {

	if (!Array.isArray(whitelist) || whitelist.length === 0) {
		return function (req, res, next) {
			res.header("Access-Control-Allow-Origin", "*");
			next();
		};
	}

	return function (req, res, next) {
		const clientIp = resolveClientIp(req);

		if (isAllowed(clientIp, whitelist)) {
			res.header("Access-Control-Allow-Origin", "*");
			next();
		} else {
			Log.warn(`IP ${clientIp} is not allowed to access the mirror`);
			res.status(403).send("This device is not allowed to access your mirror. <br> Please check your config.js or config.js.sample to change this.");
		}
	};
}







function socketIpAccessControl (whitelist) {

	if (!Array.isArray(whitelist) || whitelist.length === 0) {
		return function (req, callback) {
			callback(null, true);
		};
	}

	return function (req, callback) {
		const clientIp = resolveClientIp(req);
		if (isAllowed(clientIp, whitelist)) {
			callback(null, true);
		} else {
			Log.warn(`IP ${clientIp} is not allowed to connect to the mirror socket`);
			callback("This device is not allowed to access your mirror.", false);
		}
	};
}

module.exports = { ipAccessControl, socketIpAccessControl };
