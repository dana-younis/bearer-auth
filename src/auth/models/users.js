'use strict';

process.env.SECRET = 'dana';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Adds a virtual field to the schema. We can see it, but it never persists
// So, on every user object ... this.token is now readable!

// every time we sign in or sign up we generate anew token,every req in same sign in time will have same token but when logout it will changed
// SECRET to uniq value that just you now it ,to ensure you are the own of code , edintefair for token
users.virtual('token').get(function () {
  let tokenObject = {
    username: this.username,
  };
  return jwt.sign(tokenObject, process.env.SECRET, { expiresIn: '15s' });
});

users.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

// BASIC AUTH
users.statics.authenticateBasic = async function (username, password) {
  // to git the user name
  const user = await this.findOne({ username });
  //to check the password correct
  console.log('user', user);
  const valid = await bcrypt.compare(password, user.password);
  if (valid) {
    return user;
  }
  throw new Error('Invalid User');
};

// BEARER AUTH
// to generate Token
users.statics.authenticateWithToken = async function (token) {
  try {
    // parsedToken to make sure what ever you sign in db it will retain back to yoy then make sure this person exist or not
    const parsedToken = jwt.verify(token, process.env.SECRET);
    console.log(parsedToken);

    const user = this.findOne({ username: parsedToken.username });
    if (user) {
      return user;
    }
    throw new Error('User Not Found');
  } catch (e) {
    throw new Error(e.message);
  }
};

module.exports = mongoose.model('users', users);
