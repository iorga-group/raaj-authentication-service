module.exports = function(grunt) {
	// Project configuration.
	var config = grunt.initConfig({
		karma: {
			unit: {
				configFile: 'test/karma.conf.js'
			}
		},
		wiredep: { // inspired by http://stackoverflow.com/a/21843207/535203
			target: {
				src: 'test/karma.conf.js',
				fileTypes: {
					js: {
						block: /(([ \t]*)\/\/\s*bower:*(\S*))(\n|\r|.)*?(\/\/\s*endbower)/gi,
						detect: {
							js: /".*\.js"/gi
						},
						replace: {
							js: '"{{filePath}}",'
						}
					}
				}
			}
		}
	});

	grunt.loadNpmTasks('grunt-karma');
	grunt.loadNpmTasks('grunt-wiredep');
	grunt.registerTask('test', 'Run all tests', [ 'wiredep', 'test:unit' ]);

	grunt.registerTask('test:unit', 'Runs all unit tests with PhantomJS', function() {
		grunt.task.run('karma:unit');
	});
};
