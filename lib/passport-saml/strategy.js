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
  this._assertionName = options.assertionName;
}

function getProviderId(profile) {
  return profile.issuer + (profile.audience ? ':' + profile.audience : '');
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
Strategy.prototype.authenticate = function (req) {
  var self = this;

  var error;

  var assertionName = self._assertionName || 'assertion';
  var assertion_param = req.body[assertionName] || req.query[assertionName];

  if (!assertion_param) {
    console.error('missing assertion parameter');
    error = new Error('missing assertion parameter');
    error.status = 401;
    return self.fail(error);
  }

  var assertion = new Buffer(assertion_param, 'base64').toString();
  saml.parse(assertion, function (err, profile) {
    if (err) {
      console.error('Unable to parse assertion');
      error = new Error('Unable to parse assertion');
      error.status = 401;
      return self.fail(error);
    }
    // get the org
    self._orgRepository.find({ idprovider_id : getProviderId(profile) })
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
        self._orgPropertiesService.getValues(org.id)
          .then(function (properties) {
            if (properties && properties.identity_management && properties.identity_management.saml) {
              var issuer = properties.identity_management.saml.issuer;
              var public_key = properties.identity_management.saml.public_key;
              var audience = properties.identity_management.saml.audience;
              var bypass_expiration = properties.identity_management.saml.bypass_expiration;
              console.log('org saml properties issuer %j, audience %j, bypass_expiration %j', issuer, audience, bypass_expiration, {});
              saml.validate(assertion, {
                bypassExpiration : bypass_expiration,
                publicKey : public_key,
                audience : audience
              }, function (err, profile) {
                if (err) {
                  error = new Error('Unable to validate assertion');
                  error.status = 401;
                  return self.fail(err);
                }
                var claims = profile.claims;
                var issuer = profile.issuer;
                var email = profile.claims.email['#'];
                var company = profile.claims.company ? profile.claims.company['#'] : '';
                var firstname = profile.claims.firstname ? profile.claims.firstname['#'] : '';
                var lastname = profile.claims.lastname ? profile.claims.lastname['#'] : '';
                var username = profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']['#'];

                function verified(err, user) {
                  if (err) {
                    return self.error(err);
                  } else if (!user) {
                    return self.fail();
                  }
                  self.success(user);
                }

                if (self._passReqToCallback) {
                  self._verify(req, profile, issuer, claims, username, email, company, firstname, lastname, org, verified, properties);
                } else {
                  self._verify(profile, issuer, claims, username, email, company, firstname, lastname, org, verified, properties);
                }

              });
            } else {
              console.error('missing identity management configuration');
              error = new Error('missing identity management configuration');
              error.status = 401;
              return self.fail(error);
            }
          })
          .catch(function (err) {
            return self.error(err);
          });
      })
      .catch(function (err) {
        console.error('caught error. no org?');
        return self.fail(err);
      });
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
