'use strict';

// Helper functions for accessing the Wordpress API plugin .
var OAuthV2 = require('./OAuth1ClientV2');
var Parse = require('parse/node').Parse;
var logger = require('../logger').default;
var url = require('url');

// Returns a promise that fulfills iff this user id is valid.
function validateAuthData(authData, options) {
  options = handleMultipleConfigurations(authData, options);
  var client = new OAuthV2(options);
  var urlClient = url.parse(options.url);
  client.host = urlClient.host +  (urlClient.port ? ':' + urlClient.port : '' );
  client.auth_token = authData.auth_token;
  client.auth_token_secret = authData.auth_token_secret;
  client.protocol = urlClient.protocol;
  client.typeOAuth = 'get'; 
  
  
  return client.get(urlClient.pathname + "/wp-json/wp/v2/users/me").then(function (data) {
	var id = "0";
	
	if ( data.indexOf('{') === 0 && data.lastIndexOf('}') === data.length - 1 ) {
		data = JSON.parse(data);
		id = data.id;
	}
	
    if (id == authData.id) {
      return;
    }
    throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Wordpress auth is invalid for this user.');
  });
}

// Returns a promise that fulfills iff this app id is valid.
function validateAppId() {
  return Promise.resolve();
}

function handleMultipleConfigurations(authData, options) {
  if (Array.isArray(options)) {
    (function () {
      var consumer_key = authData.consumer_key;
      var url = authData.url;
      if (!consumer_key) {
        logger.error('Wordpress Auth', 'Multiple Wordpress configurations are available, by no consumer_key was sent by the client.');
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Wordpress auth is invalid for this user.');
      } else if ( !url ) {
    	  logger.error('Wordpress Auth', 'Multiple Wordpress configurations are available, by no Url was sent by the client.');
          throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Wordpress auth is invalid for this user.');  
      } 
      
      options = options.filter(function (option) {
        return (option.consumer_key == consumer_key) && (option.url == url);
      });

      if (options.length == 0) {
        logger.error('Wordpress Auth', 'Cannot find a configuration for the provided consumer_key');
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Wordpress auth is invalid for this user.');
      }
      options = options[0];
    })();
  }
  return options;
}

module.exports = {
  validateAppId: validateAppId,
  validateAuthData: validateAuthData,
  handleMultipleConfigurations: handleMultipleConfigurations
};
