var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');
var validator = require('validator');
var jwt = require('jsonwebtoken');

JWT_SECRET = process.env.JWT_SECRET;


var schema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },

  description: {
    type: Text
  }
});
console.log("foo");
module.exports = mongoose.model('Team', schema);
