const express = require("express");
const Log = require("logger");
const { replaceSecretPlaceholder } = require("#server_functions");








function getAllowedSecrets (moduleName) {
	const modules = global.configRedacted?.modules || [];
	const moduleConfig = modules.find((m) => m.module === moduleName);
	const allowed = new Set();
	if (moduleConfig) {

		for (const [, secretName] of JSON.stringify(moduleConfig).matchAll(/\*\*(SECRET_[^*]+)\*\*/g)) {
			allowed.add(secretName);
		}
	}
	return allowed;
}

class NodeHelper {
	init () {
		Log.log("Initializing new module helper ...");
	}

	loaded () {
		Log.log(`Module helper loaded: ${this.name}`);
	}

	start () {
		Log.log(`Starting module helper: ${this.name}`);
	}






	stop () {
		Log.log(`Stopping module helper: ${this.name}`);
	}






	socketNotificationReceived (notification, payload) {
		Log.log(`${this.name} received a socket notification: ${notification} - Payload: ${payload}`);
	}





	setName (name) {
		this.name = name;
	}





	setPath (path) {
		this.path = path;
	}








	sendSocketNotification (notification, payload) {
		this.io.of(this.name).emit(notification, payload);
	}








	setExpressApp (app) {
		this.expressApp = app;

		app.use(`/${this.name}`, express.static(`${this.path}/public`));
	}








	setSocketIO (io) {
		this.io = io;

		Log.log(`Connecting socket for: ${this.name}`);

		io.of(this.name).on("connection", (socket) => {

			socket.onAny((notification, payload) => {
				if (config?.hideConfigSecrets && payload && typeof payload === "object") {
					try {

						const allowedSecrets = getAllowedSecrets(this.name);

						const payloadStr = replaceSecretPlaceholder(JSON.stringify(payload), allowedSecrets);
						this.socketNotificationReceived(notification, JSON.parse(payloadStr));
					} catch (e) {
						Log.error("Error substituting variables in payload: ", e);
						this.socketNotificationReceived(notification, payload);
					}
				} else {
					this.socketNotificationReceived(notification, payload);
				}
			});
		});
	}






	static checkFetchStatus (response) {

		if (response.ok) {
			return response;
		} else {
			throw Error(response.statusText);
		}
	}







	static checkFetchError (error) {
		let error_type = "MODULE_ERROR_UNSPECIFIED";
		if (error.code === "EAI_AGAIN") {
			error_type = "MODULE_ERROR_NO_CONNECTION";
		} else {
			const message = typeof error.message === "string" ? error.message.toLowerCase() : "";
			if (message.includes("unauthorized") || message.includes("http 401") || message.includes("http 403")) {
				error_type = "MODULE_ERROR_UNAUTHORIZED";
			}
		}
		return error_type;
	}






	static create (moduleDefinition) {
		return class extends NodeHelper {
			constructor () {
				super();
				Object.assign(this, moduleDefinition);
				this.init();
			}
		};
	}
}

module.exports = NodeHelper;
