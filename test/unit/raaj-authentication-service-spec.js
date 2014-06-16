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
	
	it('should be able to add a bypass security header', function() {
		var raajAuthenticationService;
		
		module('raajAuthenticationService', 'raajSecurityUtils');
		inject(function(_raajAuthenticationService_) {
			raajAuthenticationService = _raajAuthenticationService_;
		});

		inject(function($http, $rootScope, $httpBackend, RaajAesUtil) {
			// mocking login
			$httpBackend.expect("GET", "api/security/getTime")
				.respond(200, new Date().getTime());
			// logging in
			$rootScope.$broadcast('raaj:auth-tryLogin' , 'user', 'password');
			$httpBackend.flush();
			
			// mocking bypass
			var token = 'testtoken',
				iv = '123456789abcdef0123456789abcdef0',
				salt = '123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
				keySize = 128,
				iterationCount = 50,
				aesUtil = new RaajAesUtil(keySize, iterationCount),
				encryptedToken = aesUtil.encrypt(salt, iv, 'password', token);
			
			$httpBackend.expect("GET", "api/security/createBypassSecurityToken").respond(200, {
				salt: salt,
				iv: iv,
				keySize: keySize,
				iterationCount: iterationCount,
				encryptedToken: encryptedToken
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
			var headerAdded = false;
			raajAuthenticationService.addBypassSecurityTokenHeader(request, function() {
				headerAdded = true;
			});
			$httpBackend.flush();
			
			expect(headerAdded).toBe(true);
			expect(request.headers['X-IRAJ-BypassSecurityToken']).toBeDefined();
		});
	});
});
