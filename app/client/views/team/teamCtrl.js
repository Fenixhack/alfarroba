angular.module('reg')
  .controller('TeamCtrl', [
    '$scope',
    'currentUser',
    'settings',
    'Utils',
    'UserService',
    'TeamService',
    'TEAM',
    function($scope, currentUser, settings, Utils, UserService, TeamService, TEAM){
      // Get the current user's most recent data.
      var Settings = settings.data;

      $scope.regIsOpen = Utils.isRegOpen(Settings);
      $scope.user = currentUser.data;
      $scope.TEAM = TEAM;
      
      function _populateTeam() {
        TeamService
          .get($scope.user.teamCode)
          .success(function(team) {
            $scope.team = team.name;
          });
      }

      function _populateTeammates() {
        UserService
          .getMyTeammates()
          .success(function(users){
            $scope.error = null;
            $scope.teammates = users;
          });
      }

      if ($scope.user.teamCode){
        _populateTeammates();
        _populateTeam();
      }

      $scope.joinTeam = function(){
        UserService
          .joinOrCreateTeam($scope.code)
          .success(function(user){
            $scope.error = null;
            $scope.user = user;
            _populateTeammates();
          })
          .error(function(res){
            $scope.error = res.message;
          });
      };

      $scope.leaveTeam = function(){
        UserService
          .leaveTeam()
          .success(function(user){
            $scope.error = null;
            $scope.user = user;
            $scope.teammates = [];
          })
          .error(function(res){
            $scope.error = res.data.message;
          });
      };

    }]);
