
require("./alias-resolver");

const fs = require("node:fs");
const path = require("node:path");
const Spawn = require("node:child_process").spawn;
const Log = require("logger");

// global absolute root path
global.root_path = path.resolve(`${__dirname}/../`);


const { setGlobalDispatcher, Agent } = require("undici");

const Server = require("./server");
const Utils = require("./utils");
const { ConfigError } = require("./utils");

const { getEnvVarsAsObj } = require("#server_functions");

const fetch_timeout = process.env.mmFetchTimeout !== undefined ? process.env.mmFetchTimeout : 30000;


global.version = require(`${global.root_path}/package.json`).version;
global.mmTestMode = process.env.mmTestMode === "true";
Log.log(`Starting MagicMirror: v${global.version}`);


Spawn("node ./js/systeminformation.js", {
	env: {
		...process.env,
		ELECTRON_VERSION: `${process.versions.electron}`,
		USED_NODE_VERSION: `${process.versions.node}`
	},
	cwd: this.root_path,
	shell: true,
	detached: true,
	stdio: "inherit"
});

if (process.env.MM_CONFIG_FILE) {
	global.configuration_file = process.env.MM_CONFIG_FILE.replace(`${global.root_path}/`, "");
}



if (process.env.MM_PORT) {
	global.mmPort = process.env.MM_PORT;
}



process.on("uncaughtException", function (err) {

	if (!err.stack.includes("node_modules/systeminformation")) {
		Log.error("Whoops! There was an uncaught exception...");
		Log.error(err);
		Log.error("MagicMirror² will not quit, but it might be a good idea to check why this happened. Maybe no internet connection?");
		Log.error("If you think this really is an issue, please open an issue on GitHub: https://github.com/MagicMirrorOrg/MagicMirror/issues");
	}
});





function App () {
	let nodeHelpers = [];
	let httpServer;
	let defaultModules;
	let env;





	function loadModule (module) {
		const elements = module.split("/");
		const moduleName = elements[elements.length - 1];
		let moduleFolder = path.resolve(`${global.root_path}/${env.modulesDir}`, module);

		if (defaultModules.includes(moduleName)) {
			const defaultModuleFolder = path.resolve(`${global.root_path}/${global.defaultModulesDir}/`, module);
			if (!global.mmTestMode) {
				moduleFolder = defaultModuleFolder;
			} else {

				if (env.modulesDir === "modules" || env.modulesDir === "tests/mocks") {
					moduleFolder = defaultModuleFolder;
				}
			}
		}

		const moduleFile = `${moduleFolder}/${moduleName}.js`;

		try {
			fs.accessSync(moduleFile, fs.constants.R_OK);
		} catch {
			Log.warn(`No ${moduleFile} found for module: ${moduleName}.`);
		}

		const helperPath = `${moduleFolder}/node_helper.js`;

		let loadHelper = true;
		try {
			fs.accessSync(helperPath, fs.constants.R_OK);
		} catch {
			loadHelper = false;
			Log.log(`No helper found for module: ${moduleName}.`);
		}


		if (loadHelper) {
			let Module;
			try {
				Module = require(helperPath);
			} catch (e) {
				Log.error(`Error when loading ${moduleName}:`, e.message);
				return;
			}
			let m = new Module();

			if (m.requiresVersion) {
				Log.log(`Check MagicMirror² version for node helper '${moduleName}' - Minimum version: ${m.requiresVersion} - Current version: ${global.version}`);
				if (cmpVersions(global.version, m.requiresVersion) >= 0) {
					Log.log("Version is ok!");
				} else {
					Log.warn(`Version is incorrect. Skip module: '${moduleName}'`);
					return;
				}
			}

			m.setName(moduleName);
			m.setPath(path.resolve(moduleFolder));
			nodeHelpers.push(m);

			m.loaded();
		}
	}






	async function loadModules (modules) {
		Log.log("Loading module helpers ...");

		for (let module of modules) {
			await loadModule(module);
		}

		Log.log("All module helpers loaded.");
	}








	function cmpVersions (a, b) {
		let i, diff;
		const regExStrip0 = /(\.0+)+$/;
		const segmentsA = a.replace(regExStrip0, "").split(".");
		const segmentsB = b.replace(regExStrip0, "").split(".");
		const l = Math.min(segmentsA.length, segmentsB.length);

		for (i = 0; i < l; i++) {
			diff = parseInt(segmentsA[i], 10) - parseInt(segmentsB[i], 10);
			if (diff) {
				return diff;
			}
		}
		return segmentsA.length - segmentsB.length;
	}








	this.start = async function () {
		try {
			const configObj = Utils.loadConfig();
			global.config = configObj.fullConf;
			const config = global.config;
			Utils.checkConfigFile(configObj);

			global.defaultModulesDir = config.defaultModulesDir;
			defaultModules = require(`${global.root_path}/${global.defaultModulesDir}/defaultmodules`);

			Log.setLogLevel(config.logLevel);

			env = getEnvVarsAsObj();

			if ((!fs.existsSync(`${global.root_path}/${env.customCss}`)) && (fs.existsSync(`${global.root_path}/css/custom.css`))) {
				try {
					fs.renameSync(`${global.root_path}/css/custom.css`, `${global.root_path}/${env.customCss}`);
					Log.warn(`WARNING! Your custom css file was moved from ${global.root_path}/css/custom.css to ${global.root_path}/${env.customCss}`);
				} catch {
					Log.warn("WARNING! Your custom css file is currently located in the css folder. Please move it to the config folder!");
				}
			}


			Utils.getModulePositions();

			let modules = [];
			for (const module of config.modules) {
				if (module.disabled) continue;
				if (module.module) {
					if (Utils.moduleHasValidPosition(module.position) || typeof (module.position) === "undefined") {

						if (!modules.includes(module.module)) {
							modules.push(module.module);
						}
					} else {
						Log.warn("Invalid module position found for this configuration:" + `\n${JSON.stringify(module, null, 2)}`);
					}
				} else {
					Log.warn("No module name found for this configuration:" + `\n${JSON.stringify(module, null, 2)}`);
				}
			}

			setGlobalDispatcher(new Agent({ connect: { timeout: fetch_timeout } }));

			await loadModules(modules);

			httpServer = new Server(configObj);
			const { app, io } = await httpServer.open();
			Log.log("Server started ...");

			const nodePromises = [];
			for (let nodeHelper of nodeHelpers) {
				nodeHelper.setExpressApp(app);
				nodeHelper.setSocketIO(io);

				try {
					nodePromises.push(nodeHelper.start());
				} catch (error) {
					Log.error(`Error when starting node_helper for module ${nodeHelper.name}:`);
					Log.error(error);
				}
			}

			const results = await Promise.allSettled(nodePromises);


			results.forEach((result) => {
				if (result.status === "rejected") {
					Log.error(result.reason);
				}
			});

			Log.log("Sockets connected & modules started ...");

			return global.config;
		} catch (err) {

			if (!(err instanceof ConfigError)) {
				Log.error("Unexpected error during startup:", err);
			}

			const int32 = new Int32Array(new SharedArrayBuffer(4));

			Atomics.wait(int32, 0, 0, 1000);
			process.exit(1);
		}
	};









	this.stop = async function () {
		const nodePromises = [];
		for (let nodeHelper of nodeHelpers) {
			try {
				if (typeof nodeHelper.stop === "function") {
					nodePromises.push(nodeHelper.stop());
				}
			} catch (error) {
				Log.error(`Error when stopping node_helper for module ${nodeHelper.name}:`);
				Log.error(error);
			}
		}

		const results = await Promise.allSettled(nodePromises);


		results.forEach((result) => {
			if (result.status === "rejected") {
				Log.error(result.reason);
			}
		});

		Log.log("Node_helpers stopped ...");



		if (!httpServer) {
			return Promise.resolve();
		}

		return httpServer.close();
	};








	process.on("SIGINT", async () => {
		Log.log("[SIGINT] Received. Shutting down server...");
		setTimeout(() => {
			process.exit(0);
		}, 3000);
		await this.stop();
		process.exit(0);
	});





	process.on("SIGTERM", async () => {
		Log.log("[SIGTERM] Received. Shutting down server...");
		setTimeout(() => {
			process.exit(0);
		}, 3000);
		await this.stop();
		process.exit(0);
	});
}

module.exports = new App();
