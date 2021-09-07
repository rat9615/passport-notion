// Module dependencies
const passport = require('passport-strategy');
const url = require('url');
const https = require('https');
const util = require('util');

function Strategy(options, verify) {
  options = options || {};

  passport.Strategy.call(this);
  this.name = 'notion';

  this._verify = verify;
  this._options = options;
  this._clientSecret = options.clientSecret;
  this._clientID = options.clientID;
  this._tokenURL = options.tokenURL || 'https://api.notion.com/v1/oauth/token';
  this._authorizationURL =
    options.authorizationURL || 'https://api.notion.com/v1/oauth/authorize';
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.code) {
    self.getOAuthAccessToken(req.query.code, function (status, oauthData) {
      if (status === 'error') {
        return self.error(oauthData);
      } else if (status === 'success') {
        self.getUserProfile(
          oauthData,
          function (userProfileStatus, userProfileData) {
            if (userProfileStatus === 'error') {
              return self.error(userProfileData);
            } else if (userProfileStatus === 'success') {
              self._verify(
                req,
                oauthData.access_token,
                userProfileData,
                function (user) {
                  self.success(user);
                }
              );
            }
          }
        );
      }
    });
  } else {
    var authUrlObject = url.parse(self._authorizationURL);
    var params = {
      client_id: self._clientID,
      redirect_uri: self._options.callbackURL,
      response_type: 'code',
      // state: self._options.state || undefined,
    };

    authUrlObject.query = params;

    var location = url.format(authUrlObject);

    this.redirect(location);
  }
};

Strategy.prototype.getOAuthAccessToken = function (code, done) {
  var accessTokenURLObject = url.parse(this._tokenURL);
  var accessTokenParams = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: options.callbackURL,
  };

  accessTokenURLObject.query = accessTokenParams;
  var accessTokenURL = url.format(accessTokenURLObject);
  accessTokenURLObject = url.parse(accessTokenURL);
  const encodedCredential = Buffer.from(
    `${this._clientID}:${this._clientSecret}`
  ).toString('base64');

  const requestOptions = {
    hostname: accessTokenURLObject.hostname,
    path: accessTokenURLObject.path,
    headers: `Basic ${encodedCredential}`,
    method: 'GET',
  };

  const accessTokenRequest = https.request(requestOptions, (res) => {
    res.on('data', (d) => {
      const accessTokenObject = JSON.parse(d);
      done('success', accessTokenObject);
    });
  });

  accessTokenRequest.on('error', (error) => {
    done('error', error);
  });

  accessTokenRequest.end();
};

// Expose strategy
module.exports = Strategy;
