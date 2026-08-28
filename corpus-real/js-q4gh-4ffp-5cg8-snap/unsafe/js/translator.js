/* global translations */

const Translator = (function () {






	async function loadJSON (file) {
		const baseHref = document.baseURI;
		const url = new URL(file, baseHref);

		try {
			const response = await fetch(url);
			if (!response.ok) {
				throw new Error(`Unexpected response status: ${response.status}`);
			}
			return await response.json();
		} catch {
			Log.error(`Loading json file =${file} failed`);
			return null;
		}
	}

	return {
		coreTranslations: {},
		coreTranslationsFallback: {},
		translations: {},
		translationsFallback: {},








		translate (module, key, variables = {}) {










			function createStringFromTemplate (template, variables) {
				if (Object.prototype.toString.call(template) !== "[object String]") {
					return template;
				}
				let templateToUse = template;
				if (variables.fallback && !template.match(new RegExp("{.+}"))) {
					templateToUse = variables.fallback;
				}
				return templateToUse.replace(new RegExp("{([^}]+)}", "g"), function (_unused, varName) {
					return varName in variables ? variables[varName] : `{${varName}}`;
				});
			}

			if (this.translations[module.name] && key in this.translations[module.name]) {
				return createStringFromTemplate(this.translations[module.name][key], variables);
			}

			if (key in this.coreTranslations) {
				return createStringFromTemplate(this.coreTranslations[key], variables);
			}

			if (this.translationsFallback[module.name] && key in this.translationsFallback[module.name]) {
				return createStringFromTemplate(this.translationsFallback[module.name][key], variables);
			}

			if (key in this.coreTranslationsFallback) {
				return createStringFromTemplate(this.coreTranslationsFallback[key], variables);
			}

			return key;
		},







		async load (module, file, isFallback) {
			Log.log(`[translator] ${module.name} - Load translation${isFallback ? " fallback" : ""}: ${file}`);

			if (this.translationsFallback[module.name]) {
				return;
			}

			const json = await loadJSON(module.file(file));
			const property = isFallback ? "translationsFallback" : "translations";
			this[property][module.name] = json;
		},





		async loadCoreTranslations (lang) {
			if (lang in translations) {
				Log.log(`[translator] Loading core translation file: ${translations[lang]}`);
				this.coreTranslations = await loadJSON(translations[lang]);
			} else {
				Log.log("[translator] Configured language not found in core translations.");
			}

			await this.loadCoreTranslationsFallback();
		},





		async loadCoreTranslationsFallback () {
			let first = Object.keys(translations)[0];
			if (first) {
				Log.log(`[translator] Loading core translation fallback file: ${translations[first]}`);
				this.coreTranslationsFallback = await loadJSON(translations[first]);
			}
		}
	};
}());

window.Translator = Translator;
