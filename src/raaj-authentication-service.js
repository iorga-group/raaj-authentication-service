/*
 * Copyright (C) 2013 Iorga Group
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */
(function () {
    'use strict';
    // based on https://github.com/witoldsz/angular-http-auth/blob/master/src/http-auth-interceptor.js

    angular.module('raajAuthenticationService', ['raajSecurityUtils'])
        .provider('raajAuthenticationService', function() {
            var getTimeApiUrl = 'api/security/getTime',
            	createBypassSecurityTokenApiUrl = 'api/security/createBypassSecurityToken';
            this.setGetTimeApiUrl = function (getTimeApiUrlParam) {
                getTimeApiUrl = getTimeApiUrlParam;
            };
            this.setCreateBypassSecurityTokenApiUrl = function (createBypassSecurityTokenApiUrlParam) {
            	createBypassSecurityTokenApiUrl = createBypassSecurityTokenApiUrlParam;
            }

            function AuthenticationService($injector, $rootScope) {
                var queryBuffer = [],
                    $http,
                    RaajAesUtil,
                    raajSecurityUtils,
                    authenticationService = this;

                this.login = null;
                this.digestedPassword = null;
                this.authenticated = false;
                this.timeShifting = 0;

                this.tryLogin = function(login, digestedPassword) {
                    authenticationService.login = login;
                    authenticationService.digestedPassword = digestedPassword;
                    $http = $http || $injector.get('$http');	// Lazy inject
                    $http.get(getTimeApiUrl, {authenticating: true})
                        .success(function(data, status, headers, config) {
                            // data : server time
                            authenticationService.timeShifting = new Date().getTime() - data;
                            authenticationService.authenticated = true;
                            $rootScope.$broadcast('raaj:auth-loginSucced', data, status, headers, config);
                            authenticationService.retryAllQueries();
                        })
                        .error(function(data, status, headers, config) {
                            $rootScope = $rootScope || $injector.get('$rootScope');	// Lazy inject
                            $rootScope.$broadcast('raaj:auth-loginFailed', data, status, headers, config);
                        });
                };
                this.appendQuery = function(config, deferred) {
                    queryBuffer.push({
                        config: config,
                        deferred: deferred
                    });
                };
                this.retryAllQueries = function() {
                    for (var i = 0; i < queryBuffer.length; ++i) {
                        authenticationService.retryHttpRequest(queryBuffer[i].config, queryBuffer[i].deferred);
                    }
                };
                this.retryHttpRequest = function(config, deferred) {
                    authenticationService.addAuthorizationHeader(config);
                    return deferred.resolve(config);
                };
                this.addAuthorizationHeader = function(config) {
                    // Adding the date header considering the time shifting
                    config.headers['X-RAAJ-Date'] = new Date(new Date().getTime() - authenticationService.timeShifting).toUTCString();

                    raajSecurityUtils = raajSecurityUtils || $injector.get('raajSecurityUtils'); // Lazy inject
                    raajSecurityUtils.addAuthorizationHeader(authenticationService.login, authenticationService.digestedPassword, {
                        method: config.method,
                        body: config.transformRequest[0](config.data),
                        headers: config.headers,
                        resource: config.url.substring(3, config.url.length)
                    });
                };
                this.createBypassSecurityToken = function(callbackFn) {
                	RaajAesUtil = RaajAesUtil || $injector.get('RaajAesUtil'); // Lazy inject
                	$http = $http || $injector.get('$http');	// Lazy inject
                	
            		$http.get(createBypassSecurityTokenApiUrl).success(function(data) {
						var aesUtil = new RaajAesUtil(data.keySize, data.iterationCount);
						var bypassSecurityToken = aesUtil.decrypt(data.salt, data.iv, authenticationService.digestedPassword, data.encryptedToken);
						
						callbackFn(bypassSecurityToken);
            		});
                };
                this.addBypassSecurityTokenHeader = function (config, callbackFn) {
                	authenticationService.createBypassSecurityToken(function(bypassSecurityToken) {
                		config.headers['X-IRAJ-BypassSecurityToken'] = bypassSecurityToken;
                		callbackFn();
                	});
                }
            };

            this.$get = function ($injector, $rootScope) {
                return new AuthenticationService($injector, $rootScope);
            };
        })
        .run(function($rootScope, raajAuthenticationService) {
            $rootScope.$on('raaj:auth-tryLogin', function(event, login, digestedPassword) {
                raajAuthenticationService.tryLogin(login, digestedPassword);
            });
        })
    ;
})();