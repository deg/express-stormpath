'use strict';

var oauth = require('../oauth');
var loginResponder = require('./login-responder');
var exchangeStormpathToken = require('./exchange-stormpath-token');

/**
 * loginWithOAuthProvider takes provider data, such as an access token,
 * and responds with a new session if the provider data is valid.
 *
 * @method
 *
 * @param {Object} options - Should contain the provider data sent to application.getAccount.
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports = function loginWithOAuthProvider(options, req, res) {
  var config = req.app.get('stormpathConfig');
  var application = req.app.get('stormpathApplication');
  var preLoginHandler = config.preLoginHandler;
  var postLoginHandler = config.postLoginHandler;
  var preRegistrationHandler = config.preRegistrationHandler;
  var postRegistrationHandler = config.postRegistrationHandler;

  application.getAccount(options, function (err, providerAccountResult) {
    if (err) {
      return oauth.errorResponder(req, res, err);
    }

    var account = providerAccountResult.account;

    function continueWithTokenExchange() {
      exchangeStormpathToken(req, account, function (err, authenticationResult) {
        if (err) {
          return oauth.errorResponder(req, res, err);
        }

        loginResponder(authenticationResult, account, req, res);
      });
    }

    function continueWithHandlers(preHandler, postHandler, onCompleted) {
      preHandler(options, req, res, function (err) {
        if (err) {
          return oauth.errorResponder(req, res, err);
        }

        if (postHandler) {
          return postHandler(account, req, res, function (err) {
            if (err) {
              return oauth.errorResponder(req, res, err);
            }

            onCompleted();
          });
        }

        onCompleted();
      });
    }

    if (preRegistrationHandler && providerAccountResult.created) {
      return continueWithHandlers(preRegistrationHandler, postRegistrationHandler, function () {
        continueWithHandlers(preLoginHandler, postLoginHandler, continueWithTokenExchange);
      });
    }

    if (preLoginHandler) {
      return continueWithHandlers(preLoginHandler, postLoginHandler, continueWithTokenExchange);
    }

    continueWithTokenExchange();
  });
};
