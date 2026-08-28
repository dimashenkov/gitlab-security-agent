"use strict";

const electron = require("electron");
const core = require("./app");
const Log = require("./logger");
const { applyElectronSwitches } = require("./electron_helper");


let config = process.env.config ? JSON.parse(process.env.config) : {};

const app = electron.app;






if (process.env.ELECTRON_ENABLE_GPU !== "1") {
	app.disableHardwareAcceleration();
}


const BrowserWindow = electron.BrowserWindow;





let mainWindow;




function createWindow () {





	let electronSize = { width: 800, height: 600 };
	try {
		electronSize = electron.screen.getPrimaryDisplay().workAreaSize;
	} catch {
		Log.warn("Could not get display size, using defaults ...");
	}

	applyElectronSwitches(app.commandLine, config.electronSwitches);
	let electronOptionsDefaults = {
		width: electronSize.width,
		height: electronSize.height,
		icon: "favicon.svg",
		x: 0,
		y: 0,
		darkTheme: true,
		webPreferences: {
			contextIsolation: true,
			nodeIntegration: false,
			zoomFactor: config.zoom
		},
		backgroundColor: "#000000"
	};

	electronOptionsDefaults.show = false;
	electronOptionsDefaults.frame = false;
	electronOptionsDefaults.transparent = true;
	electronOptionsDefaults.hasShadow = false;
	electronOptionsDefaults.fullscreen = true;

	const electronOptions = Object.assign({}, electronOptionsDefaults, config.electronOptions);

	if (process.env.MOCK_DATE !== undefined) {

		const fakeNow = new Date(process.env.MOCK_DATE).valueOf();
		Date = class extends Date {
			constructor (...args) {
				if (args.length === 0) {
					super(fakeNow);
				} else {
					super(...args);
				}
			}
		};
		const __DateNowOffset = fakeNow - Date.now();
		const __DateNow = Date.now;
		Date.now = () => __DateNow() + __DateNowOffset;
	}


	mainWindow = new BrowserWindow(electronOptions);






	let prefix;
	if ((config.tls !== null && config.tls) || config.useHttps) {
		prefix = "https://";
	} else {
		prefix = "http://";
	}

	let address = (config.address === void 0) | (config.address === "") | (config.address === "0.0.0.0") ? (config.address = "localhost") : config.address;
	const port = process.env.MM_PORT || config.port;
	mainWindow.loadURL(`${prefix}${address}:${port}`);


	if (process.argv.includes("dev")) {
		if (process.env.mmTestMode) {

			const devtools = new BrowserWindow(electronOptions);
			mainWindow.webContents.setDevToolsWebContents(devtools.webContents);
		}
		mainWindow.webContents.openDevTools();
	}


	mainWindow.webContents.on("dom-ready", () => {
		mainWindow.webContents.sendInputEvent({ type: "mouseMove", x: 0, y: 0 });
	});


	mainWindow.on("closed", function () {
		mainWindow = null;
	});


	mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
		let curHeaders = details.responseHeaders;
		if (config.ignoreXOriginHeader || false) {
			curHeaders = Object.fromEntries(Object.entries(curHeaders).filter((header) => !(/x-frame-options/i).test(header[0])));
		}

		if (config.ignoreContentSecurityPolicy || false) {
			curHeaders = Object.fromEntries(Object.entries(curHeaders).filter((header) => !(/content-security-policy/i).test(header[0])));
		}

		callback({ responseHeaders: curHeaders });
	});

	mainWindow.once("ready-to-show", () => {
		mainWindow.show();
	});
}


app.on("window-all-closed", function () {
	if (process.env.mmTestMode) {

		app.quit();
	} else {
		createWindow();
	}
});

app.on("activate", function () {





	if (mainWindow === null) {
		createWindow();
	}
});








app.on("before-quit", async (event) => {
	Log.log("Shutting down server...");
	event.preventDefault();
	setTimeout(() => {
		process.exit(0);
	}, 3000);
	await core.stop();
	process.exit(0);
});




app.on("certificate-error", (event, webContents, url, error, certificate, callback) => {
	event.preventDefault();
	callback(true);
});

if (process.env.clientonly) {
	app.whenReady().then(() => {
		Log.log("Launching client viewer application.");
		createWindow();
	});
}





if (["localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1", undefined].includes(config.address)) {
	core.start().then((c) => {
		config = c;
		app.whenReady().then(() => {
			Log.log("Launching application.");
			createWindow();
		});
	});
}
