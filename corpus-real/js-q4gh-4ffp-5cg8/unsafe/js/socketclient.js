/* global io */

export const MMSocket = function (moduleName) {
	if (typeof moduleName !== "string") {
		throw new Error("Please set the module name for the MMSocket.");
	}

	this.moduleName = moduleName;


	let base = "/";
	if (typeof config !== "undefined" && typeof config.basePath !== "undefined") {
		base = config.basePath;
	}
	this.socket = io(`/${this.moduleName}`, {
		path: `${base}socket.io`,
		pingInterval: 120000,
		pingTimeout: 120000
	});

	let notificationCallback = function () {};

	const onevent = this.socket.onevent;
	this.socket.onevent = (packet) => {
		const args = packet.data || [];
		onevent.call(this.socket, packet);
		packet.data = ["*"].concat(args);
		onevent.call(this.socket, packet);
	};


	this.socket.on("*", (notification, payload) => {
		if (notification !== "*") {
			notificationCallback(notification, payload);
		}
	});


	this.setNotificationCallback = (callback) => {
		notificationCallback = callback;
	};

	this.sendNotification = (notification, payload = {}) => {
		this.socket.emit(notification, payload);
	};
};


if (!globalThis.MMSocket) globalThis.MMSocket = MMSocket;
