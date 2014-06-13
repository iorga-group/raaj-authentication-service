module.exports = function(config) {
	config.set({
		// base path, that will be used to resolve files and exclude
		//basePath : '../',

		// list of files / patterns to load in the browser
		files : [
		    // bower:js
		    "../bower_components/angular/angular.js",
		    "../bower_components/cryptojslib/components/core.js",
		    "../bower_components/cryptojslib/components/md5.js",
		    "../bower_components/cryptojslib/components/sha1.js",
		    "../bower_components/cryptojslib/components/hmac.js",
		    "../bower_components/cryptojslib/components/enc-base64.js",
		    "../bower_components/cryptojslib/components/evpkdf.js",
		    "../bower_components/cryptojslib/components/cipher-core.js",
		    "../bower_components/cryptojslib/components/aes.js",
		    "../bower_components/cryptojslib/components/pbkdf2.js",
		    "../bower_components/raaj-security-utils/src/raaj-security-utils.js",
		    // endbower
			'../bower_components/angular-mocks/angular-mocks.js',
			'../src/raaj-authentication-service.js',
			'unit/**/*.js'
		],

		// list of files to exclude
		exclude : [],

		frameworks : [ 'jasmine' ],

		// test results reporter to use
		// possible values: 'dots', 'progress', 'junit', 'growl', 'coverage'
		reporters : [ 'progress' ],

		// enable / disable colors in the output (reporters and logs)
		colors : true,

		// enable / disable watching file and executing tests whenever any file
		// changes
		autoWatch : false,

		browsers : [ 'PhantomJS' ],

		singleRun : true
	});
};