// Module dependencies
const passport = require('passport-strategy');
const url = require('url');
const https = require('https');
const util = require('util');

function Strategy(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) {
    throw new TypeError("NotionStrategy requires a verify callback");
  }
  if (!options.clientID) {
    throw new TypeError("NotionStrategy requires a clientID");
  }
  if (!options.clientSecret) {
    throw new TypeError("NotionStrategy requires a clientSecret");
  }
  if (!options.callbackURL) {
    throw new TypeError("NotionStrategy require an Callback URL option");
  }

  passport.Strategy.call(this);
  this.name = 'notion';

  this._verify = verify;
  this._options = options;
  this._clientSecret = options.clientSecret;
  this._clientID = options.clientID;
  this._tokenURL = options.tokenURL || 'https://api.notion.com/v1/oauth/token';
  this._authorizationURL =
    options.authorizationURL || 'https://api.notion.com/v1/oauth/authorize';
  this._getProfileURL = options.getProfileURL || 'https://api.notion.com/v1/users'
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  const self = this; 
  if (req.query && req.query.code) {
    self.getOAuthAccessToken(req.query.code, function (status, oauthData) {
      if (status === 'error') {
        return self.error(oauthData);
      } else if (status === 'success') {
        self.getUserProfile(oauthData, function (
          userProfileStatus,
          userProfileData
        ) {
          if (userProfileStatus === "error") {
            return self.error(userProfileData);
          } else if (userProfileStatus === "success") {
            self._verify(
              req,
              oauthData.access_token,
              undefined,
              oauthData,
              userProfileData,
              function (user) {
                self.success(user);
              }
            );
          }
        });
      }
    });
  } else {
    const authUrlObject = url.parse(self._authorizationURL);
    const params = {
      client_id: self._clientID,
      redirect_uri: self._options.callbackURL,
      response_type: 'code',
    };
    if(self._options?.state) params.state = self._options.state;
    authUrlObject.query = params;
    const location = url.format(authUrlObject);
    this.redirect(location);
  }
};

Strategy.prototype.getOAuthAccessToken = function (code, done) {
  let accessTokenURLObject = url.parse(this._tokenURL);
  const accessTokenBody = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: this._options.callbackURL,
  };

  const accessTokenURL = url.format(accessTokenURLObject);
  accessTokenURLObject = url.parse(accessTokenURL);
  const encodedCredential = Buffer.from(
    `${this._clientID}:${this._clientSecret}`
  ).toString('base64');

  const requestOptions = {
    hostname: accessTokenURLObject.hostname,
    path: accessTokenURLObject.path,
    headers: { 'Authorization': `Basic ${encodedCredential}`,
              'Content-Type': 'application/json'},
    method: 'POST',

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

  accessTokenRequest.write(JSON.stringify(accessTokenBody));
  accessTokenRequest.end();
};

Strategy.prototype.getUserProfile = function (accessTokenObject, done) {
  let userProfileObject = url.parse(this._getProfileURL);

  const userProfileURL = url.format(userProfileObject);
  userProfileObject = url.parse(userProfileURL);

  const requestOptions = {
    hostname: userProfileObject.hostname,
    path: userProfileObject.path,
    headers:{
      Authorization: `Bearer ${accessTokenObject.access_token}`,
      'Notion-Version':'2021-08-16'
    },
    method: "GET",
  };

  const accessTokenRequest = https.request(requestOptions, (res) => {
    res.on("data", (d) => {
      const userProfile = JSON.parse(d);
      done("success", userProfile);
    });
  });

  accessTokenRequest.on("error", (error) => {
    done("error", error);
  });

  accessTokenRequest.end();
};

// Expose strategy
module.exports = Strategy;
