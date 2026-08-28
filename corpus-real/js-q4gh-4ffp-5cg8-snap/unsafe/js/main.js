/* global addAnimateCSS, removeAnimateCSS, AnimateCSSIn, AnimateCSSOut, modulePositions, io */

// eslint-disable-next-line import-x/extensions
import { Loader } from "./loader.js";

let modules = [];




function createDomObjects () {
	const domCreationPromises = [];

	modules.forEach(function (module) {
		if (typeof module.data.position !== "string") {
			return;
		}

		let haveAnimateIn = null;

		if (module.data.animateIn && AnimateCSSIn.indexOf(module.data.animateIn) !== -1) haveAnimateIn = module.data.animateIn;

		const wrapper = selectWrapper(module.data.position);

		const dom = document.createElement("div");
		dom.id = module.identifier;
		dom.className = module.name;

		if (typeof module.data.classes === "string") {
			dom.className = `module ${dom.className} ${module.data.classes}`;
		}

		dom.style.order = (typeof module.data.order === "number" && Number.isInteger(module.data.order)) ? module.data.order : 0;

		dom.opacity = 0;
		wrapper.appendChild(dom);

		const moduleHeader = document.createElement("header");
		moduleHeader.innerHTML = module.getHeader();
		moduleHeader.className = "module-header";
		dom.appendChild(moduleHeader);

		if (typeof module.getHeader() === "undefined" || module.getHeader() !== "") {
			moduleHeader.style.display = "none;";
		} else {
			moduleHeader.style.display = "block;";
		}

		const moduleContent = document.createElement("div");
		moduleContent.className = "module-content";
		dom.appendChild(moduleContent);



		var domCreationPromise;
		if (haveAnimateIn) domCreationPromise = _updateDom(module, { options: { speed: 1000, animate: { in: haveAnimateIn } } }, true);
		else domCreationPromise = _updateDom(module, 0);

		domCreationPromises.push(domCreationPromise);
		domCreationPromise
			.then(function () {
				_sendNotification("MODULE_DOM_CREATED", null, null, module);
			})
			.catch(Log.error);
	});

	updateWrapperStates();

	Promise.all(domCreationPromises).then(function () {
		_sendNotification("DOM_OBJECTS_CREATED");
	});
}






function selectWrapper (position) {
	const classes = position.replace("_", " ");
	const parentWrapper = document.getElementsByClassName(classes);
	if (parentWrapper.length > 0) {
		const wrapper = parentWrapper[0].getElementsByClassName("container");
		if (wrapper.length > 0) {
			return wrapper[0];
		}
	}
}








function _sendNotification (notification, payload, sender, sendTo) {
	for (const m in modules) {
		const module = modules[m];
		if (module !== sender && (!sendTo || module === sendTo)) {
			module.notificationReceived(notification, payload, sender);
		}
	}
}








function _updateDom (module, updateOptions, createAnimatedDom = false) {
	return new Promise(function (resolve) {
		let speed = updateOptions;
		let animateOut = null;
		let animateIn = null;
		if (typeof updateOptions === "object") {
			if (typeof updateOptions.options === "object" && updateOptions.options.speed !== undefined) {
				speed = updateOptions.options.speed;
				Log.debug(`updateDom: ${module.identifier} Has speed in object: ${speed}`);
				if (typeof updateOptions.options.animate === "object") {
					animateOut = updateOptions.options.animate.out;
					animateIn = updateOptions.options.animate.in;
					Log.debug(`updateDom: ${module.identifier} Has animate in object: out->${animateOut}, in->${animateIn}`);
				}
			} else {
				Log.debug(`updateDom: ${module.identifier} Has no speed in object`);
				speed = 0;
			}
		}

		const newHeader = module.getHeader();
		let newContentPromise = module.getDom();

		if (!(newContentPromise instanceof Promise)) {

			newContentPromise = Promise.resolve(newContentPromise);
		}

		newContentPromise
			.then(function (newContent) {
				const updatePromise = updateDomWithContent(module, speed, newHeader, newContent, animateOut, animateIn, createAnimatedDom);

				updatePromise.then(resolve).catch(Log.error);
			})
			.catch(Log.error);
	});
}












async function updateDomWithContent (module, speed, newHeader, newContent, animateOut, animateIn, createAnimatedDom = false) {
	if (module.hidden || !speed) {
		updateModuleContent(module, newHeader, newContent);
		return;
	}

	if (!moduleNeedsUpdate(module, newHeader, newContent)) {
		return;
	}

	if (createAnimatedDom && animateIn !== null) {
		Log.debug(`${module.identifier} createAnimatedDom (${animateIn})`);
		updateModuleContent(module, newHeader, newContent);
		if (!module.hidden) {
			_showModule(module, speed, null, { animate: animateIn });
		}
		return;
	}

	await new Promise((resolve) => {
		_hideModule(
			module,
			speed / 2,
			function () {
				updateModuleContent(module, newHeader, newContent);
				if (!module.hidden) {
					_showModule(module, speed / 2, null, { animate: animateIn });
				}
				resolve();
			},
			{ animate: animateOut }
		);
	});
}








function moduleNeedsUpdate (module, newHeader, newContent) {
	const moduleWrapper = document.getElementById(module.identifier);
	if (moduleWrapper === null) {
		return false;
	}

	const contentWrapper = moduleWrapper.getElementsByClassName("module-content");
	const headerWrapper = moduleWrapper.getElementsByClassName("module-header");

	let headerNeedsUpdate = false;
	let contentNeedsUpdate;

	if (headerWrapper.length > 0) {
		headerNeedsUpdate = newHeader !== headerWrapper[0].innerHTML;
	}

	const tempContentWrapper = document.createElement("div");
	tempContentWrapper.appendChild(newContent);
	contentNeedsUpdate = tempContentWrapper.innerHTML !== contentWrapper[0].innerHTML;

	return headerNeedsUpdate || contentNeedsUpdate;
}







function updateModuleContent (module, newHeader, newContent) {
	const moduleWrapper = document.getElementById(module.identifier);
	if (moduleWrapper === null) {
		return;
	}
	const headerWrapper = moduleWrapper.getElementsByClassName("module-header");
	const contentWrapper = moduleWrapper.getElementsByClassName("module-content");

	contentWrapper[0].innerHTML = "";
	contentWrapper[0].appendChild(newContent);

	headerWrapper[0].innerHTML = newHeader;
	if (headerWrapper.length > 0 && newHeader) {
		headerWrapper[0].style.display = "block";
	} else {
		headerWrapper[0].style.display = "none";
	}
}








function _hideModule (module, speed, callback, options = {}) {

	if (options.lockString) {
		if (module.lockStrings.indexOf(options.lockString) === -1) {
			module.lockStrings.push(options.lockString);
		}
	}

	const moduleWrapper = document.getElementById(module.identifier);
	if (moduleWrapper !== null) {
		clearTimeout(module.showHideTimer);

		if (module.hasAnimateOut) {
			removeAnimateCSS(module.identifier, module.hasAnimateOut);
			Log.debug(`${module.identifier} Force remove animateOut (in hide): ${module.hasAnimateOut}`);
			module.hasAnimateOut = false;
		}
		if (module.hasAnimateIn) {
			removeAnimateCSS(module.identifier, module.hasAnimateIn);
			Log.debug(`${module.identifier} Force remove animateIn (in hide): ${module.hasAnimateIn}`);
			module.hasAnimateIn = false;
		}



		let haveAnimateName = null;

		if (module.data.animateOut && AnimateCSSOut.indexOf(module.data.animateOut) !== -1) haveAnimateName = module.data.animateOut;

		else if (options.animate && AnimateCSSOut.indexOf(options.animate) !== -1) haveAnimateName = options.animate;

		if (haveAnimateName) {

			Log.debug(`${module.identifier} Has animateOut: ${haveAnimateName}`);
			module.hasAnimateOut = haveAnimateName;
			addAnimateCSS(module.identifier, haveAnimateName, speed / 1000);
			module.showHideTimer = setTimeout(function () {
				removeAnimateCSS(module.identifier, haveAnimateName);
				Log.debug(`${module.identifier} Remove animateOut: ${module.hasAnimateOut}`);

				moduleWrapper.style.opacity = 0;
				moduleWrapper.classList.add("hidden");
				moduleWrapper.style.position = "fixed";
				module.hasAnimateOut = false;

				updateWrapperStates();
				if (typeof callback === "function") {
					callback();
				}
			}, speed);
		} else {

			moduleWrapper.style.transition = `opacity ${speed / 1000}s`;
			moduleWrapper.style.opacity = 0;
			moduleWrapper.classList.add("hidden");
			module.showHideTimer = setTimeout(function () {




				moduleWrapper.style.position = "fixed";

				updateWrapperStates();

				if (typeof callback === "function") {
					callback();
				}
			}, speed);
		}
	} else {

		if (typeof callback === "function") {
			callback();
		}
	}
}








function _showModule (module, speed, callback, options = {}) {

	if (options.lockString) {
		const index = module.lockStrings.indexOf(options.lockString);
		if (index !== -1) {
			module.lockStrings.splice(index, 1);
		}
	}



	if (module.lockStrings.length !== 0 && options.force !== true) {
		Log.log(`Will not show ${module.name}. LockStrings active: ${module.lockStrings.join(",")}`);
		if (typeof options.onError === "function") {
			options.onError(new Error("LOCK_STRING_ACTIVE"));
		}
		return;
	}

	if (module.hasAnimateOut) {
		removeAnimateCSS(module.identifier, module.hasAnimateOut);
		Log.debug(`${module.identifier} Force remove animateOut (in show): ${module.hasAnimateOut}`);
		module.hasAnimateOut = false;
	}
	if (module.hasAnimateIn) {
		removeAnimateCSS(module.identifier, module.hasAnimateIn);
		Log.debug(`${module.identifier} Force remove animateIn (in show): ${module.hasAnimateIn}`);
		module.hasAnimateIn = false;
	}

	module.hidden = false;


	if (module.lockStrings.length !== 0 && options.force === true) {
		Log.log(`Force show of module: ${module.name}`);
		module.lockStrings = [];
	}

	const moduleWrapper = document.getElementById(module.identifier);
	if (moduleWrapper !== null) {
		clearTimeout(module.showHideTimer);




		let haveAnimateName = null;

		if (module.data.animateIn && AnimateCSSIn.indexOf(module.data.animateIn) !== -1) haveAnimateName = module.data.animateIn;

		else if (options.animate && AnimateCSSIn.indexOf(options.animate) !== -1) haveAnimateName = options.animate;

		if (!haveAnimateName) moduleWrapper.style.transition = `opacity ${speed / 1000}s`;

		moduleWrapper.style.position = "static";
		moduleWrapper.classList.remove("hidden");

		updateWrapperStates();


		void moduleWrapper.parentElement.parentElement.offsetHeight;
		moduleWrapper.style.opacity = 1;

		if (haveAnimateName) {

			Log.debug(`${module.identifier} Has animateIn: ${haveAnimateName}`);
			module.hasAnimateIn = haveAnimateName;
			addAnimateCSS(module.identifier, haveAnimateName, speed / 1000);
			module.showHideTimer = setTimeout(function () {
				removeAnimateCSS(module.identifier, haveAnimateName);
				Log.debug(`${module.identifier} Remove animateIn: ${haveAnimateName}`);
				module.hasAnimateIn = false;
				if (typeof callback === "function") {
					callback();
				}
			}, speed);
		} else {

			module.showHideTimer = setTimeout(function () {
				if (typeof callback === "function") {
					callback();
				}
			}, speed);
		}
	} else {

		if (typeof callback === "function") {
			callback();
		}
	}
}












function updateWrapperStates () {
	modulePositions.forEach(function (position) {
		const wrapper = selectWrapper(position);
		const moduleWrappers = wrapper.getElementsByClassName("module");

		let showWrapper = false;
		Array.prototype.forEach.call(moduleWrappers, function (moduleWrapper) {
			if (moduleWrapper.style.position === "" || moduleWrapper.style.position === "static") {
				showWrapper = true;
			}
		});


		wrapper.className = showWrapper ? "container" : "container hidden";
	});
}




async function loadConfig () {
	try {
		const res = await fetch(new URL("config/", `${location.origin}${config.basePath}`));




		config = JSON.parse(await res.text(), (key, value) => {
			if (value && typeof value === "object" && typeof value.__mmFunction === "string") {
				try {
					return new Function(`return (${value.__mmFunction})`)();
				} catch {
					Log.warn(`Failed to revive function for config key "${key}".`);
				}
			}
			return value;
		});
	} catch (error) {
		Log.error("Unable to retrieve config", error);
	}
}





function setSelectionMethodsForModules (modules) {






	function withClass (className) {
		return modulesByClass(className, true);
	}






	function exceptWithClass (className) {
		return modulesByClass(className, false);
	}







	function modulesByClass (className, include) {
		let searchClasses = className;
		if (typeof className === "string") {
			searchClasses = className.split(" ");
		}

		const newModules = modules.filter(function (module) {
			const classes = module.data.classes.toLowerCase().split(" ");

			for (const searchClass of searchClasses) {
				if (classes.indexOf(searchClass.toLowerCase()) !== -1) {
					return include;
				}
			}

			return !include;
		});

		setSelectionMethodsForModules(newModules);
		return newModules;
	}






	function exceptModule (module) {
		const newModules = modules.filter(function (mod) {
			return mod.identifier !== module.identifier;
		});

		setSelectionMethodsForModules(newModules);
		return newModules;
	}





	function enumerate (callback) {
		modules.map(function (module) {
			callback(module);
		});
	}

	if (typeof modules.withClass === "undefined") {
		Object.defineProperty(modules, "withClass", { value: withClass, enumerable: false });
	}
	if (typeof modules.exceptWithClass === "undefined") {
		Object.defineProperty(modules, "exceptWithClass", { value: exceptWithClass, enumerable: false });
	}
	if (typeof modules.exceptModule === "undefined") {
		Object.defineProperty(modules, "exceptModule", { value: exceptModule, enumerable: false });
	}
	if (typeof modules.enumerate === "undefined") {
		Object.defineProperty(modules, "enumerate", { value: enumerate, enumerable: false });
	}
}

export const MM = {






	async init () {
		Log.info("Initializing MagicMirror².");
		await loadConfig();

		Log.setLogLevel(config.logLevel);

		await globalThis.Translator.loadCoreTranslations(config.language);
		await Loader.loadModules();
	},





	modulesStarted (moduleObjects) {
		modules = [];
		let startUp = "";

		moduleObjects.forEach((module) => modules.push(module));

		Log.info("All modules started!");
		_sendNotification("ALL_MODULES_STARTED");

		createDomObjects();


		if (typeof io !== "undefined") {
			const socket = io("/", {
				path: `${config.basePath || "/"}socket.io`
			});

			socket.on("RELOAD", () => {
				Log.warn("Reload notification received from server");
				window.location.reload(true);
			});
		}

		if (config.reloadAfterServerRestart) {
			setInterval(async () => {


				try {
					const res = await fetch(`${location.protocol}//${location.host}${config.basePath}startup`);
					const curr = await res.text();
					if (startUp === "") startUp = curr;
					if (startUp !== curr) {
						startUp = "";
						window.location.reload(true);
						Log.warn("Refreshing Website because server was restarted");
					}
				} catch (err) {
					Log.error(`MagicMirror not reachable: ${err}`);
				}
			}, config.checkServerInterval);
		}
	},







	sendNotification (notification, payload, sender) {
		if (arguments.length < 3) {
			Log.error("sendNotification: Missing arguments.");
			return;
		}

		if (typeof notification !== "string") {
			Log.error("sendNotification: Notification should be a string.");
			return;
		}

		if (!(sender instanceof Module)) {
			Log.error("sendNotification: Sender should be a module.");
			return;
		}


		_sendNotification(notification, payload, sender);
	},






	updateDom (module, updateOptions) {
		if (!(module instanceof Module)) {
			Log.error("updateDom: Sender should be a module.");
			return;
		}

		if (!module.data.position) {
			Log.warn("module tries to update the DOM without being displayed.");
			return;
		}


		_updateDom(module, updateOptions).then(function () {

			_sendNotification("MODULE_DOM_UPDATED", null, null, module);
		});
	},





	getModules () {
		setSelectionMethodsForModules(modules);
		return modules;
	},








	hideModule (module, speed, callback, options) {
		module.hidden = true;
		_hideModule(module, speed, callback, options);
	},








	showModule (module, speed, callback, options) {

		_showModule(module, speed, callback, options);
	},


	getAvailableModulePositions: modulePositions
};


if (!globalThis.MM) globalThis.MM = MM;

MM.init();
