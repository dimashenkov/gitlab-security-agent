/* global nunjucks */

// eslint-disable-next-line import-x/extensions
import { Loader } from "./loader.js";
// eslint-disable-next-line import-x/extensions
import { MMSocket } from "./socketclient.js";





export class Module {




	constructor () {

		this.showHideTimer = null;





		this.lockStrings = [];






		this._nunjucksEnvironment = null;
	}










	init () {
	}




	start () {
		Log.info(`Starting module: ${this.name}`);
	}





	getScripts () {
		return [];
	}





	getStyles () {
		return [];
	}







	getTranslations () {
		return false;
	}







	getDom () {
		return new Promise((resolve) => {
			const div = document.createElement("div");
			const template = this.getTemplate();
			const templateData = this.getTemplateData();


			if ((/^.*((\.html)|(\.njk))$/).test(template)) {

				this.nunjucksEnvironment().render(template, templateData, function (err, res) {
					if (err) {
						Log.error(err);
					}

					div.innerHTML = res;

					resolve(div);
				});
			} else {

				div.innerHTML = this.nunjucksEnvironment().renderString(template, templateData);

				resolve(div);
			}
		});
	}







	getHeader () {
		return this.data.header;
	}








	getTemplate () {
		return `<div class="normal">${this.name}</div><div class="small dimmed">${this.identifier}</div>`;
	}






	getTemplateData () {
		return {};
	}







	notificationReceived (notification, payload, sender) {
		if (sender) {
			Log.debug(`${this.name} received a module notification: ${notification} from sender: ${sender.name}`);
		} else {
			Log.debug(`${this.name} received a system notification: ${notification}`);
		}
	}






	nunjucksEnvironment () {
		if (this._nunjucksEnvironment !== null) {
			return this._nunjucksEnvironment;
		}

		this._nunjucksEnvironment = new nunjucks.Environment(new nunjucks.WebLoader(this.file(""), { async: true }), {
			trimBlocks: true,
			lstripBlocks: true
		});

		this._nunjucksEnvironment.addFilter("translate", (str, variables) => {
			return nunjucks.runtime.markSafe(this.translate(str, variables));
		});

		return this._nunjucksEnvironment;
	}






	socketNotificationReceived (notification, payload) {
		Log.log(`${this.name} received a socket notification: ${notification} - Payload: ${payload}`);
	}




	suspend () {
		Log.log(`${this.name} is suspended.`);
	}




	resume () {
		Log.log(`${this.name} is resumed.`);
	}











	setData (data) {
		this.data = data;
		this.name = data.name;
		this.identifier = data.identifier;
		this.hidden = false;
		this.hasAnimateIn = false;
		this.hasAnimateOut = false;

		this.setConfig(data.config, data.configDeepMerge);
	}






	setConfig (config, deep) {
		this.config = deep ? configMerge({}, this.defaults, config) : Object.assign({}, this.defaults, config);
	}






	socket () {
		if (typeof this._socket === "undefined") {
			this._socket = new MMSocket(this.name);
		}

		this._socket.setNotificationCallback((notification, payload) => {
			this.socketNotificationReceived(notification, payload);
		});

		return this._socket;
	}






	file (file) {
		return `${this.data.path}/${file}`.replace("//", "/");
	}





	loadStyles () {
		return this.loadDependencies("getStyles");
	}





	loadScripts () {
		return this.loadDependencies("getScripts");
	}






	async loadDependencies (funcName) {
		let dependencies = this[funcName]();

		const loadNextDependency = async () => {
			if (dependencies.length > 0) {
				const nextDependency = dependencies[0];
				await Loader.loadFileForModule(nextDependency, this);
				dependencies = dependencies.slice(1);
				await loadNextDependency();
			} else {
				return Promise.resolve();
			}
		};

		await loadNextDependency();
	}





	async loadTranslations () {
		const translations = this.getTranslations() || {};
		const language = config.language.toLowerCase();

		const languages = Object.keys(translations);
		const fallbackLanguage = languages[0];

		if (languages.length === 0) {
			return;
		}

		const translationFile = translations[language];
		const translationsFallbackFile = translations[fallbackLanguage];

		if (!translationFile) {
			return Translator.load(this, translationsFallbackFile, true);
		}

		await Translator.load(this, translationFile, false);

		if (translationFile !== translationsFallbackFile) {
			return Translator.load(this, translationsFallbackFile, true);
		}
	}








	translate (key, defaultValueOrVariables, defaultValue) {
		if (typeof defaultValueOrVariables === "object") {
			return Translator.translate(this, key, defaultValueOrVariables) || defaultValue || "";
		}
		return Translator.translate(this, key) || defaultValueOrVariables || "";
	}





	updateDom (updateOptions) {
		MM.updateDom(this, updateOptions);
	}






	sendNotification (notification, payload) {
		MM.sendNotification(notification, payload, this);
	}






	sendSocketNotification (notification, payload) {
		this.socket().sendNotification(notification, payload);
	}







	hide (speed, callback, options = {}) {
		let usedCallback = callback || function () {};
		let usedOptions = options;

		if (typeof callback === "object") {
			Log.error("Parameter mismatch in module.hide: callback is not an optional parameter!");
			usedOptions = callback;
			usedCallback = function () {};
		}

		MM.hideModule(
			this,
			speed,
			() => {
				this.suspend();
				usedCallback();
			},
			usedOptions
		);
	}







	show (speed, callback, options) {
		let usedCallback = callback || function () {};
		let usedOptions = options;

		if (typeof callback === "object") {
			Log.error("Parameter mismatch in module.show: callback is not an optional parameter!");
			usedOptions = callback;
			usedCallback = function () {};
		}

		MM.showModule(
			this,
			speed,
			() => {
				this.resume();
				usedCallback();
			},
			usedOptions
		);
	}
}

globalThis.Module = Module;























function configMerge (result) {
	const stack = Array.prototype.slice.call(arguments, 1);
	let item, key;

	while (stack.length) {
		item = stack.shift();
		for (key in item) {
			if (item.hasOwnProperty(key)) {
				if (typeof result[key] === "object" && result[key] && Object.prototype.toString.call(result[key]) !== "[object Array]") {
					if (typeof item[key] === "object" && item[key] !== null) {
						result[key] = configMerge({}, result[key], item[key]);
					} else {
						result[key] = item[key];
					}
				} else {
					result[key] = item[key];
				}
			}
		}
	}
	return result;
}

Module.definitions = {};

Module.create = function (name) {

	if (!Module.definitions[name]) {
		return;
	}

	const moduleDefinition = Module.definitions[name];
	const clonedDefinition = cloneObject(moduleDefinition);
	const className = typeof name === "string" && name.trim() ? name : "AnonymousModule";


	const SubClass = {
		[className]: class extends Module {
			constructor () {
				super();
				Object.assign(this, clonedDefinition);
				if (typeof this.init === "function") {
					this.init();
				}
			}
		}
	}[className];

	return new SubClass();
};

Module.register = function (name, moduleDefinition) {
	if (moduleDefinition.requiresVersion) {
		Log.log(`Check MagicMirror² version for module '${name}' - Minimum version:  ${moduleDefinition.requiresVersion} - Current version: ${window.mmVersion}`);
		if (cmpVersions(window.mmVersion, moduleDefinition.requiresVersion) >= 0) {
			Log.log("Version is ok!");
		} else {
			Log.warn(`Version is incorrect. Skip module: '${name}'`);
			return;
		}
	}
	Log.log(`Module registered: ${name}`);
	Module.definitions[name] = moduleDefinition;
};








export function cmpVersions (a, b) {
	const regExStrip0 = /(\.0+)+$/;
	const segmentsA = a.replace(regExStrip0, "").split(".");
	const segmentsB = b.replace(regExStrip0, "").split(".");
	const l = Math.min(segmentsA.length, segmentsB.length);

	for (let i = 0; i < l; i++) {
		let diff = parseInt(segmentsA[i], 10) - parseInt(segmentsB[i], 10);
		if (diff) {
			return diff;
		}
	}
	return segmentsA.length - segmentsB.length;
}






export function cloneObject (obj) {
	if (obj === null || typeof obj !== "object") {
		return obj;
	}

	if (Array.isArray(obj)) {
		return obj.map((item) => cloneObject(item));
	}

	const tag = Object.prototype.toString.call(obj);

	if (tag === "[object RegExp]") {
		return new RegExp(obj);
	}

	if (tag === "[object Date]") {
		return new Date(obj.getTime());
	}

	const proto = Object.getPrototypeOf(obj);
	const isPlainObject = proto === null || Object.getPrototypeOf(proto) === null;


	if (!isPlainObject) {
		return obj;
	}

	const temp = {};
	for (const key of Object.keys(obj)) {
		temp[key] = cloneObject(obj[key]);
	}

	return temp;
}
