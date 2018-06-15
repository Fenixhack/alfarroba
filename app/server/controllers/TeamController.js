var Team = require('../models/Team');


var TeamController = {};

TeamController.getTeam = function(id, callback) {
  return Team.findOne({
    _id: id
  }, function (err, team) {
    console.log(team);
    if (err || !team) {
      return callback(err);
    }
    return callback(err, team);
  })
}

module.exports = TeamController;