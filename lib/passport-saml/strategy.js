/**
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 */

'use strict';

var passport = require('passport');
var util = require('util');
var saml = require('saml20');
var Promise = require('bluebird');

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
  if (!options.orgPropertiesService) throw new Error('SAML 2.0 authentication strategy requires a org_properties_service');
  if (!options.orgRepository) throw new Error('SAML 2.0 authentication strategy requires a org_repository');

  passport.Strategy.call(this);
  this.name = 'saml';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this._orgPropertiesService = options.orgPropertiesService;
  this._orgRepository = options.orgRepository;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on a SAML 2.0 assertion
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};

  var error;

  var assertion_param = req.body.assertion || req.query.assertion;

  if (!assertion_param) {
    logger.error('missing assertion parameter');
    error = new Error('missing assertion parameter');
    error.status = 401;
    return this.fail(error);
  }

  var assertion = new Buffer(assertion_param, 'base64').toString();
  saml.parse(assertion, function (err, profile) {
    if (err) {
      logger.error('Unable to parse assertion');
      error = new Error('Unable to parse assertion');
      error.status = 401;
      return this.fail(error);
    }
    // get the org
    this._orgRepository.find({ idprovider_id : profile.issuer })
      .then(function (orgs) {
        return new Promise(function (resolve, reject) {
          if (orgs && orgs.data && orgs.data[0]) {
            resolve(orgs.data[0]);
          } else {
            reject();
          }
        });
      })
      .then(function (org) {
        this._orgPropertiesService.getValues(org.id)
          .then(function (properties) {
            if (properties && properties.identity_management && properties.identity_management.saml) {
              var issuer = properties.identity_management.saml.issuer;
              var public_key = properties.identity_management.saml.public_key;
              var audience = properties.identity_management.saml.audience;
              var bypass_expiration = properties.identity_management.saml.bypass_expiration;
              logger.debug('org saml properties issuer %j, audience %j, bypass_expiration %j', issuer, audience, bypass_expiration, {});
              saml.validate(assertion, {
                bypassExpiration : bypass_expiration,
                publicKey : public_key,
                audience : audience
              }, function (err, profile) {
                if (err) {
                  error = new Error('Unable to validate assertion');
                  error.status = 401;
                  return next(error);
                }
                var claims = profile.claims;
                var issuer = profile.issuer;
                var email = profile.claims.email['#'];
                var company = profile.claims.company['#'];
                var firstname = profile.claims.firstname['#'];
                var lastname = profile.claims.lastname['#'];
                var username = profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']['#'];

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
                  this._verify(req, profile, issuer, claims, username, email, company, firstname, lastname, org, verified);
                } else {
                  this._verify(profile, issuer, claims, username, email, company, firstname, lastname, org, verified);
                }

              });
            } else {
              logger.error('missing identity management configuration');
              error = new Error('missing identity management configuration');
              error.status = 401;
              return next(error);
            }
          })
          .catch(function (err) {
            return next(err);
          });
      });
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
