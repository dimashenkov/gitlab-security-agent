/* global mmPort */

const address = "localhost";
let port = 8080;
if (typeof mmPort !== "undefined") {
	port = mmPort;
}
const defaults = {
	address: address,
	port: port,
	basePath: "/",
	useHttps: false,
	httpsPrivateKey: "",
	httpsCertificate: "",
	tls: null,
	electronOptions: {},
	electronSwitches: [],
	ignoreXOriginHeader: false,
	ignoreContentSecurityPolicy: false,
	ipWhitelist: ["127.0.0.1", "::ffff:127.0.0.1", "::1"],
	cors: "disabled",
	corsDomainWhitelist: [],
	watchTargets: [],

	language: "en",
	logLevel: ["INFO", "LOG", "WARN", "ERROR"],
	timeFormat: 24,
	units: "metric",
	zoom: 1,
	customCss: "config/custom.css",
	foreignModulesDir: "modules",
	defaultModulesDir: "defaultmodules",
	hideConfigSecrets: false,


	httpHeaders: { contentSecurityPolicy: false, crossOriginOpenerPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false, originAgentCluster: false },



	checkServerInterval: 30 * 1000,
	reloadAfterServerRestart: false,

	modules: [
		{
			module: "updatenotification",
			position: "top_center"
		},
		{
			module: "helloworld",
			position: "upper_third",
			classes: "large thin",
			config: {
				text: "MagicMirror²"
			}
		},
		{
			module: "helloworld",
			position: "middle_center",
			config: {
				text: "Please create a config file or check the existing one for errors."
			}
		},
		{
			module: "helloworld",
			position: "middle_center",
			classes: "small dimmed",
			config: {
				text: "See README for more information."
			}
		},
		{
			module: "helloworld",
			position: "middle_center",
			classes: "xsmall",
			config: {
				text: "If you get this message while your config file is already created,<br>" + "it probably contains an error. To validate your config file run in your MagicMirror² directory<br>" + "<pre>node --run config:check</pre>"
			}
		},
		{
			module: "helloworld",
			position: "bottom_bar",
			classes: "xsmall dimmed",
			config: {
				text: "https://magicmirror.builders/"
			}
		}
	]
};


if (typeof module !== "undefined") {
	module.exports = defaults;
}
