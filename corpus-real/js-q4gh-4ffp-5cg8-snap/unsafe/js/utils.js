const fs = require("node:fs");
const { loadEnvFile } = require("node:process");

const modulePositions = [];
const regionRegEx = /"region ([^"]*)/i;
const indexFileName = "index.html";
const discoveredPositionsJSFilename = "js/positions.js";

const { styleText } = require("node:util");
const Log = require("logger");
const globals = require("globals");
const { Linter } = require("eslint");
const { getConfigFilePath } = require("#server_functions");

const linter = new Linter({ configType: "flat" });

class ConfigError extends Error {
	constructor (message) {
		super(message);
		this.name = "ConfigError";
	}
}

const requireFromString = (src) => {
	const m = new module.constructor();
	m._compile(src, "");
	return m.exports;
};


const getAvailableModulePositions = () => {
	return modulePositions;
};


const moduleHasValidPosition = (position) => {
	if (getAvailableModulePositions().indexOf(position) === -1) return false;
	return true;
};

const getModulePositions = () => {

	if (modulePositions.length === 0) {

		const lines = fs.readFileSync(indexFileName).toString().split("\n");

		lines.forEach((line) => {

			const results = regionRegEx.exec(line);

			if (results && results.length > 0) {

				const positionName = results[1].replace(" ", "_");

				if (!modulePositions.includes(positionName)) {
					modulePositions.push(positionName);
				}
			}
		});
		try {
			fs.writeFileSync(discoveredPositionsJSFilename, `const modulePositions=${JSON.stringify(modulePositions)}`);
		}
		catch {
			Log.error("unable to write js/positions.js with the discovered module positions\nmake the MagicMirror/js folder writeable by the user starting MagicMirror");
		}
	}

	return modulePositions;
};






const checkDeprecatedOptions = (userConfig) => {
	const deprecated = require(`${global.root_path}/js/deprecated`);


	const deprecatedOptions = deprecated.configs;
	const usedDeprecated = deprecatedOptions.filter((option) => userConfig.hasOwnProperty(option));
	if (usedDeprecated.length > 0) {
		Log.warn(`WARNING! Your config is using deprecated option(s): ${usedDeprecated.join(", ")}. Check README and Documentation for more up-to-date ways of getting the same functionality.`);
	}


	for (const element of userConfig.modules) {
		if (deprecated[element.module] !== undefined && element.config !== undefined) {
			const deprecatedModuleOptions = deprecated[element.module];
			const usedDeprecatedModuleOptions = deprecatedModuleOptions.filter((option) => element.config.hasOwnProperty(option));
			if (usedDeprecatedModuleOptions.length > 0) {
				Log.warn(`WARNING! Your config for module ${element.module} is using deprecated option(s): ${usedDeprecatedModuleOptions.join(", ")}. Check README and Documentation for more up-to-date ways of getting the same functionality.`);
			}
		}
	}
};





const loadConfig = () => {
	Log.log("Loading config ...");
	const defaults = require("./defaults");
	if (global.mmTestMode) {

		defaults.address = "0.0.0.0";
	}



	const configFilename = getConfigFilePath();
	let templateFile = `${configFilename}.template`;


	try {
		fs.accessSync(templateFile, fs.constants.F_OK);
		Log.warn("config.js.template files are deprecated and not used anymore. You can use variables inside config.js so copy the template file content into config.js if needed.");
	} catch {

	}


	const configEnvFile = `${configFilename.substr(0, configFilename.lastIndexOf("."))}.env`;
	try {
		if (fs.existsSync(configEnvFile)) {

			loadEnvFile(configEnvFile);
		}
	} catch (error) {
		Log.log(`${configEnvFile} does not exist. ${error.message}`);
	}


	try {
		let configContent = fs.readFileSync(configFilename, "utf-8");
		const hideConfigSecrets = configContent.match(/^\s*hideConfigSecrets: true.*$/m);
		let configContentFull = configContent;
		let configContentRedacted = hideConfigSecrets ? configContent : undefined;
		Object.keys(process.env).forEach((env) => {
			configContentFull = configContentFull.replaceAll(`\${${env}}`, process.env[env]);
			if (hideConfigSecrets) {
				if (env.startsWith("SECRET_")) {
					configContentRedacted = configContentRedacted.replaceAll(`"\${${env}}"`, `"**${env}**"`);
					configContentRedacted = configContentRedacted.replaceAll(`\${${env}}`, `**${env}**`);
				} else {
					configContentRedacted = configContentRedacted.replaceAll(`\${${env}}`, process.env[env]);
				}
			}
		});
		configContentRedacted = configContentRedacted ? configContentRedacted : configContentFull;
		const configObj = {
			configFilename: configFilename,
			configContentFull: configContentFull,
			configContentRedacted: configContentRedacted,
			redactedConf: Object.assign({}, defaults, requireFromString(configContentRedacted)),
			fullConf: Object.assign({}, defaults, requireFromString(configContentFull))
		};

		if (Object.keys(configObj.fullConf).length === 0) {
			Log.error("WARNING! Config file appears empty, maybe missing module.exports last line?");
		}
		checkDeprecatedOptions(configObj.fullConf);

		try {
			const cfg = `let config = { basePath: "${configObj.fullConf.basePath}"};`;
			fs.writeFileSync(`${global.root_path}/config/basepath.js`, cfg, "utf-8");
		} catch (error) {
			Log.error(`Could not write config/basepath.js file: ${error.message}`);
		}

		return configObj;

	} catch (error) {
		if (error.code === "ENOENT") {
			Log.error(`Could not find config file: ${configFilename}`);
		} else if (error.code === "EACCES") {
			Log.error(`No permission to read config file: ${configFilename}`);
		} else {
			Log.error(`Cannot access config file: ${configFilename}\n${error.message}`);
		}
		throw new ConfigError("");
	}
};





const checkConfigFile = (configObject) => {
	let configObj = configObject;
	if (!configObj) configObj = loadConfig();
	const configFileName = configObj.configFilename;


	Log.info(`Checking config file ${configFileName} ...`);


	const configFile = configObj.configContentFull;

	const errors = linter.verify(
		configFile,
		{
			languageOptions: {
				ecmaVersion: "latest",
				globals: {
					...globals.browser,
					...globals.node
				}
			},
			rules: {
				"no-sparse-arrays": "error",
				"no-undef": "error"
			}
		},
		configFileName
	);

	if (errors.length === 0) {
		Log.info(styleText("green", "Your configuration file doesn't contain syntax errors :)"));
		validateModulePositions(configObj.fullConf);
	} else {
		let errorMessage = "Your configuration file contains syntax errors :(";

		for (const error of errors) {
			errorMessage += `\nLine ${error.line} column ${error.column}: ${error.message}`;
		}
		Log.error(errorMessage);
		throw new ConfigError("");
	}
};











const validateModulePositions = (data) => {
	Log.info("Checking modules structure configuration ...");

	const positionList = getModulePositions();


	if (data.modules !== undefined && !Array.isArray(data.modules)) {
		Log.error("This module configuration contains errors:\nmodules must be an array");
		throw new ConfigError("");
	}


	for (const [index, mod] of (data.modules ?? []).entries()) {

		if (mod === null || typeof mod !== "object" || Array.isArray(mod)) {
			Log.error(`This module configuration contains errors:\n${JSON.stringify(mod, null, 2)}\nmodule entry must be an object`);
			throw new ConfigError("");
		}


		if (typeof mod.module !== "string") {
			Log.error(`This module configuration contains errors:\n${JSON.stringify(mod, null, 2)}\nmodule: must be a string`);
			throw new ConfigError("");
		}


		if (mod.position !== undefined && typeof mod.position !== "string") {
			Log.error(`This module configuration contains errors:\n${JSON.stringify(mod, null, 2)}\nposition: must be a string`);
			throw new ConfigError("");
		}


		if (mod.position && !positionList.includes(mod.position)) {
			Log.warn(`Module ${index} ("${mod.module}") uses unknown position: "${mod.position}"`);
			Log.warn(`Known positions are: ${positionList.join(", ")}`);
		}
	}

	Log.info(styleText("green", "Your modules structure configuration doesn't contain errors :)"));
};

module.exports = { loadConfig, getModulePositions, moduleHasValidPosition, getAvailableModulePositions, checkConfigFile, ConfigError };
