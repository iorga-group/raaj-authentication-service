function UserEditCtrl($scope, $routeParams, $http, irajMessageService, irajBreadcrumbsService) {
	/// Action methods ///
	/////////////////////
	$scope.save = function(){
		$http.post('api/administration/userEdit/save', $scope.userEditForm, {irajMessagesIdPrefix: 'userEditForm', irajClearAllMessages: true})
			.success(function(userId, status, headers, config) {
				$scope.userEditForm.userId = userId;
				irajMessageService.displayMessage({message: "L'utilisateur a bien été enregistré.", type: 'success'}, 'userEditForm');
				irajBreadcrumbsService.replace('/administration/userEdit/'+userId, "Modification d'un utilisateur");
			});
	}

	/// Initialization ///
	/////////////////////
	$http.get('api/administration/userEdit/init').success(function(data, status, headers, config) {
		$scope.profileList = data;
	});
	
	$scope.userEditForm = {
			userId : 0,
			login: "",
			password: "",
			lastName : "",
			firstName : "",
			profileId : 0,
			active : false
	};
	
	if ($routeParams.userId) {
		$scope.userEditForm.userId = $routeParams.userId;
	}
	
	if ($scope.userEditForm.userId != 0) {
		$http.get('api/administration/userEdit/find/' + $scope.userEditForm.userId).success(function(user, status, headers, config) {
			$scope.userEditForm = user;
		});
		irajBreadcrumbsService.setLastLabel("Modification d'un utilisateur");
	} else {
		irajBreadcrumbsService.setLastLabel("Création d'un utilisateur");
	}
}