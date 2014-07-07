/**
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 */

'use strict';

var passport = require('passport');
var util = require('util');

/**
 * `Strategy` constructor.
 *
 * The SAML 2.0 authentication strategy authenticates requests based on the
 * credentials submitted through a SAML 2.0 assertion.
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('SAML 2.0 authentication strategy requires a verify function');

  passport.Strategy.call(this);
  this.name = 'saml';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};

  var assertion = req.body.assertion || req.query.assertion;

  if (!assertion || !password) {
    return this.fail(new Error('Missing assertion'));
  }

  var self = this;

  function verified(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  }

  if (self._passReqToCallback) {
    this._verify(req, assertion, verified);
  } else {
    this._verify(assertion, verified);
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
