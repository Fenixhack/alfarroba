angular.module('reg')
  .factory('TeamService', [
  '$http',
  function($http) {
    var teams = '/api/teams';

    return {
      get: function(id) {
        var url = teams + '/' + id;
        return $http.get(url);
      } 
    } 
  }
]);