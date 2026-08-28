



const path = require("node:path");
const Module = require("node:module");

const root = path.join(__dirname, "..");


const ALIASES = {
	logger: "js/logger.js",
	node_helper: "js/node_helper.js"
};


const resolved = Object.fromEntries(
	Object.entries(ALIASES).map(([k, rel]) => [k, path.join(root, rel)])
);


if (!Module._mmAliasPatched) {
	const origResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request, parent, isMain, options) {
		if (Object.prototype.hasOwnProperty.call(resolved, request)) {
			return resolved[request];
		}
		return origResolveFilename.call(this, request, parent, isMain, options);
	};
	Module._mmAliasPatched = true;
}
