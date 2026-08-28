/* global defaultModules, vendor */



const loadedModuleFiles = [];
const loadedFiles = [];
const moduleObjects = [];





function getEnvVarsFromConfig () {
	return {
		modulesDir: config.foreignModulesDir || "modules",
		defaultModulesDir: config.defaultModulesDir || "defaultmodules",
		customCss: config.customCss || "config/custom.css"
	};
}





async function getEnvVars () {

	if (typeof process !== "undefined" && process.env && process.env.mmTestMode === "true") {
		return getEnvVarsFromConfig();
	}


	try {
		const res = await fetch(new URL("env", `${location.origin}${config.basePath}`));
		return JSON.parse(await res.text());
	} catch (error) {

		Log.error("Unable to retrieve env configuration", error);
		return getEnvVarsFromConfig();
	}
}




async function startModules () {
	const modulePromises = [];
	for (const module of moduleObjects) {
		try {
			modulePromises.push(module.start());
		} catch (error) {
			Log.error(`Error when starting node_helper for module ${module.name}:`);
			Log.error(error);
		}
	}

	const results = await Promise.allSettled(modulePromises);


	results.forEach((result) => {
		if (result.status === "rejected") {
			Log.error(result.reason);
		}
	});


	MM.modulesStarted(moduleObjects);


	for (const thisModule of moduleObjects) {
		if (thisModule.data.hiddenOnStartup) {
			Log.info(`Initially hiding ${thisModule.name}`);
			thisModule.hide();
		}
	}
}





function getAllModules () {
	const AllModules = config.modules.filter((module) => (module.module !== undefined) && (MM.getAvailableModulePositions.indexOf(module.position) > -1 || typeof (module.position) === "undefined"));
	return AllModules;
}





async function getModuleData () {
	const modules = getAllModules();
	const moduleFiles = [];
	const envVars = await getEnvVars();

	modules.forEach(function (moduleData, index) {
		const module = moduleData.module;

		const elements = module.split("/");
		const moduleName = elements[elements.length - 1];
		let moduleFolder = `${envVars.modulesDir}/${module}`;

		if (defaultModules.indexOf(moduleName) !== -1) {
			const defaultModuleFolder = `${envVars.defaultModulesDir}/${module}`;
			if (window.name !== "jsdom") {
				moduleFolder = defaultModuleFolder;
			} else {

				if (envVars.modulesDir === "modules") {
					moduleFolder = defaultModuleFolder;
				}
			}
		}

		if (moduleData.disabled === true) {
			return;
		}

		moduleFiles.push({
			index: index,
			identifier: `module_${index}_${module}`,
			name: moduleName,
			path: `${moduleFolder}/`,
			file: `${moduleName}.js`,
			position: moduleData.position,
			animateIn: moduleData.animateIn,
			animateOut: moduleData.animateOut,
			hiddenOnStartup: moduleData.hiddenOnStartup,
			header: moduleData.header,
			configDeepMerge: typeof moduleData.configDeepMerge === "boolean" ? moduleData.configDeepMerge : false,
			config: moduleData.config,
			classes: typeof moduleData.classes !== "undefined" ? `${moduleData.classes} ${module}` : module,
			order: (typeof moduleData.order === "number" && Number.isInteger(moduleData.order)) ? moduleData.order : 0
		});
	});

	return moduleFiles;
}






async function loadModule (module) {
	const url = module.path + module.file;




	async function afterLoad () {
		const moduleObject = Module.create(module.name);
		if (moduleObject) {
			await bootstrapModule(module, moduleObject);
		}
	}

	if (loadedModuleFiles.indexOf(url) !== -1) {
		await afterLoad();
	} else {
		await loadFile(url);
		loadedModuleFiles.push(url);
		await afterLoad();
	}
}






async function bootstrapModule (module, mObj) {
	Log.info(`Bootstrapping module: ${module.name}`);
	mObj.setData(module);

	await mObj.loadScripts();
	Log.log(`Scripts loaded for: ${module.name}`);

	await mObj.loadStyles();
	Log.log(`Styles loaded for: ${module.name}`);

	await mObj.loadTranslations();
	Log.log(`Translations loaded for: ${module.name}`);

	moduleObjects.push(mObj);
}






function loadFile (fileName) {
	const extension = fileName.slice((Math.max(0, fileName.lastIndexOf(".")) || Infinity) + 1);
	let script, stylesheet;

	switch (extension.toLowerCase()) {
		case "js":
			return new Promise((resolve) => {
				Log.log(`Load script: ${fileName}`);
				script = document.createElement("script");
				script.type = "text/javascript";
				script.src = fileName;
				script.onload = function () {
					resolve();
				};
				script.onerror = function () {
					Log.error("Error on loading script:", fileName);
					script.remove();
					resolve();
				};
				document.getElementsByTagName("body")[0].appendChild(script);
			});
		case "css":
			return new Promise((resolve) => {
				Log.log(`Load stylesheet: ${fileName}`);

				stylesheet = document.createElement("link");
				stylesheet.rel = "stylesheet";
				stylesheet.type = "text/css";
				stylesheet.href = fileName;
				stylesheet.onload = function () {
					resolve();
				};
				stylesheet.onerror = function () {
					Log.error("Error on loading stylesheet:", fileName);
					stylesheet.remove();
					resolve();
				};
				document.getElementsByTagName("head")[0].appendChild(stylesheet);
			});
	}
}



export const Loader = {




	async loadModules () {
		const moduleData = await getModuleData();
		const envVars = await getEnvVars();
		const customCss = envVars.customCss;


		for (const module of moduleData) {
			await loadModule(module);
		}




		await loadFile(customCss);


		await startModules();
	},








	loadFileForModule (fileName, module) {
		if (loadedFiles.indexOf(fileName.toLowerCase()) !== -1) {
			Log.log(`File already loaded: ${fileName}`);
			return Promise.resolve();
		}

		if (fileName.indexOf("http://") === 0 || fileName.indexOf("https://") === 0 || fileName.indexOf("/") !== -1) {


			loadedFiles.push(fileName.toLowerCase());
			return loadFile(fileName);
		}

		if (vendor[fileName] !== undefined) {


			loadedFiles.push(fileName.toLowerCase());
			return loadFile(`${vendor[fileName]}`);
		}



		loadedFiles.push(fileName.toLowerCase());
		return loadFile(module.file(fileName));
	}
};
