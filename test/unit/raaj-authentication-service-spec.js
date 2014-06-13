'use strict';

describe('raajAuthenticationService', function() {

	it('should add an authorization header', function() {
		var raajAuthenticationService;
		
		module('raajAuthenticationService');
		inject(function(_raajAuthenticationService_) {
			raajAuthenticationService = _raajAuthenticationService_;
		});
		var request = {
			method: 'GET',
			body: 'Body Test',
			headers: {
				'Content-Type': 'text/plain',
				'Date': 'Mon, 22 Apr 2013 00:00:00 GMT',
			},
			resource: '/',
			url: 'http://example.tld/',
			transformRequest: [function(data) {return data;}]
		};
		raajAuthenticationService.login = 'user';
		raajAuthenticationService.digestedPassword = 'password';
		raajAuthenticationService.addAuthorizationHeader(request);
		expect(request.headers['Authorization']).toBeDefined();
	});
});
