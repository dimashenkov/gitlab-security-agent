

const AnimateCSSIn = [

	"bounce",
	"flash",
	"pulse",
	"rubberBand",
	"shakeX",
	"shakeY",
	"headShake",
	"swing",
	"tada",
	"wobble",
	"jello",
	"heartBeat",

	"backInDown",
	"backInLeft",
	"backInRight",
	"backInUp",

	"bounceIn",
	"bounceInDown",
	"bounceInLeft",
	"bounceInRight",
	"bounceInUp",

	"fadeIn",
	"fadeInDown",
	"fadeInDownBig",
	"fadeInLeft",
	"fadeInLeftBig",
	"fadeInRight",
	"fadeInRightBig",
	"fadeInUp",
	"fadeInUpBig",
	"fadeInTopLeft",
	"fadeInTopRight",
	"fadeInBottomLeft",
	"fadeInBottomRight",

	"flip",
	"flipInX",
	"flipInY",

	"lightSpeedInRight",
	"lightSpeedInLeft",

	"rotateIn",
	"rotateInDownLeft",
	"rotateInDownRight",
	"rotateInUpLeft",
	"rotateInUpRight",

	"jackInTheBox",
	"rollIn",

	"zoomIn",
	"zoomInDown",
	"zoomInLeft",
	"zoomInRight",
	"zoomInUp",

	"slideInDown",
	"slideInLeft",
	"slideInRight",
	"slideInUp"
];

const AnimateCSSOut = [

	"backOutDown",
	"backOutLeft",
	"backOutRight",
	"backOutUp",

	"bounceOut",
	"bounceOutDown",
	"bounceOutLeft",
	"bounceOutRight",
	"bounceOutUp",

	"fadeOut",
	"fadeOutDown",
	"fadeOutDownBig",
	"fadeOutLeft",
	"fadeOutLeftBig",
	"fadeOutRight",
	"fadeOutRightBig",
	"fadeOutUp",
	"fadeOutUpBig",
	"fadeOutTopLeft",
	"fadeOutTopRight",
	"fadeOutBottomRight",
	"fadeOutBottomLeft",

	"flipOutX",
	"flipOutY",

	"lightSpeedOutRight",
	"lightSpeedOutLeft",

	"rotateOut",
	"rotateOutDownLeft",
	"rotateOutDownRight",
	"rotateOutUpLeft",
	"rotateOutUpRight",

	"hinge",
	"rollOut",

	"zoomOut",
	"zoomOutDown",
	"zoomOutLeft",
	"zoomOutRight",
	"zoomOutUp",

	"slideOutDown",
	"slideOutLeft",
	"slideOutRight",
	"slideOutUp"
];







function addAnimateCSS (element, animation, animationTime) {
	const animationName = `animate__${animation}`;
	const node = document.getElementById(element);
	if (!node) {

		Log.warn("node not found for adding", element);
		return;
	}
	node.style.setProperty("--animate-duration", `${animationTime}s`);
	node.classList.add("animate__animated", animationName);
}






function removeAnimateCSS (element, animation) {
	const animationName = `animate__${animation}`;
	const node = document.getElementById(element);
	if (!node) {

		Log.warn("node not found for removing", element);
		return;
	}
	node.classList.remove("animate__animated", animationName);
	node.style.removeProperty("--animate-duration");
}
if (typeof window === "undefined") module.exports = { AnimateCSSIn, AnimateCSSOut, addAnimateCSS, removeAnimateCSS };
