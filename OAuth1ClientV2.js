'use strict';

var https = require('https'),
    crypto = require('crypto'),
    http = require('http'),
    url = require('url');

var OAuthV2 = function OAuthV2(options) {
  this.consumer_key = options.consumer_key;
  this.consumer_secret = options.consumer_secret;
  this.auth_token = options.auth_token;
  this.auth_token_secret = options.auth_token_secret;
  this.host = options.host;
  this.protocol = options.protocol || 'https:';
  this.OAuthV2_params = options.OAuthV2_params || {};
  this.typeOAuth = options.typeOAuth || 'head';   // get, post or head
};

OAuthV2.prototype.send = function (method, path, params, body) {
	
  var request = this.buildRequest(method, path, params, body);
 
  var protocol = (this.protocol === 'https:' ? https : http); 
  // Encode the body properly, the current Parse Implementation don't do it properly
  return new Promise(function (resolve, reject) {
	
    var httpRequest = protocol.request(request, function (res) {
      var data = '';
      res.on('data', function (chunk) {
        data += chunk;
      });
      res.on('end', function () {
        resolve(data);
      });
    }).on('error', function (e) {
      reject('Failed to make an OAuthV2 request');
    });
    if (request.body) {
      httpRequest.write(request.body);
    }
    httpRequest.end();
  });
};

OAuthV2.prototype.buildRequest = function (method, path, params, body) {
  if (path.indexOf("/") != 0) {
    path = "/" + path;
  }
 
  var request = {
    host: this.host,
    path: path,
    method: method.toUpperCase(),
    protocol: this.protocol,
    typeOAuth: this.typeOAuth
  };

  var OAuthV2_params = this.OAuthV2_params || {};
  OAuthV2_params.oauth_consumer_key = this.consumer_key;
  if (this.auth_token) {
    OAuthV2_params["oauth_token"] = this.auth_token;
  }

  request = OAuthV2.signRequest(request, OAuthV2_params, this.consumer_secret, this.auth_token_secret);
  
  delete request.typeOAuth;

  if ( ( params && Object.keys( params ).length > 0 ) && 
		  ( this.typeOAuth.toLowerCase() == 'head' ) ) {
	    path += "?" + OAuthV2.buildParameterString(params);
	    request.path = path;
  } else
	  if ( this.typeOAuth.toLowerCase() == 'get' ) {
		  var paramsMerge = {};
		  params = params || {};
		  Object.assign( paramsMerge, params, OAuthV2_params );
		  path += "?" + OAuthV2.buildParameterString( paramsMerge );
		  request.path = path;
	  } else
		  if ( this.typeOAuth.toLowerCase() == 'post' ) {
			  body = body || {};
			  Object.assign( body, OAuthV2_params );
		  }

  
  if (body && Object.keys(body).length > 0) {
    request.body = OAuthV2.buildParameterString(body);
  }
  
  
  
  return request;
};

OAuthV2.prototype.get = function (path, params) {
  return this.send("GET", path, params);
};

OAuthV2.prototype.post = function (path, params, body) {
  return this.send("POST", path, params, body);
};

/*
	Proper string %escape encoding
*/
OAuthV2.encode = function (str) {
  //       discuss at: http://phpjs.org/functions/rawurlencode/
  //      original by: Brett Zamir (http://brett-zamir.me)
  //         input by: travc
  //         input by: Brett Zamir (http://brett-zamir.me)
  //         input by: Michael Grier
  //         input by: Ratheous
  //      bugfixed by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  //      bugfixed by: Brett Zamir (http://brett-zamir.me)
  //      bugfixed by: Joris
  // reimplemented by: Brett Zamir (http://brett-zamir.me)
  // reimplemented by: Brett Zamir (http://brett-zamir.me)
  //             note: This reflects PHP 5.3/6.0+ behavior
  //             note: Please be aware that this function expects to encode into UTF-8 encoded strings, as found on
  //             note: pages served as UTF-8
  //        example 1: rawurlencode('Kevin van Zonneveld!');
  //        returns 1: 'Kevin%20van%20Zonneveld%21'
  //        example 2: rawurlencode('http://kevin.vanzonneveld.net/');
  //        returns 2: 'http%3A%2F%2Fkevin.vanzonneveld.net%2F'
  //        example 3: rawurlencode('http://www.google.nl/search?q=php.js&ie=utf-8&oe=utf-8&aq=t&rls=com.ubuntu:en-US:unofficial&client=firefox-a');
  //        returns 3: 'http%3A%2F%2Fwww.google.nl%2Fsearch%3Fq%3Dphp.js%26ie%3Dutf-8%26oe%3Dutf-8%26aq%3Dt%26rls%3Dcom.ubuntu%3Aen-US%3Aunofficial%26client%3Dfirefox-a'

  str = (str + '').toString();

  // Tilde should be allowed unescaped in future versions of PHP (as reflected below), but if you want to reflect current
  // PHP behavior, you would need to add ".replace(/~/g, '%7E');" to the following.
  // Add  ".replace(/~/g, '%7E')..replace(/\s/g,'+')" for RFC 3986
  return encodeURIComponent(str).replace(/!/g, '%21').replace(/'/g, '%27').replace(/\(/g, '%28').replace(/\)/g, '%29').replace(/\*/g, '%2A').replace(/~/g, '%7E').replace(/\s/g,'+');
};

OAuthV2.signatureMethod = "HMAC-SHA1";
OAuthV2.version = "1.0";

/*
	Generate a nonce
*/
OAuthV2.nonce = function () {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (var i = 0; i < 30; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }return text;
};

OAuthV2.buildParameterString = function (obj) {
  var result = {};

  // Sort keys and encode values
  if (obj) {
    var keys = Object.keys(obj).sort();

    // Map key=value, join them by &
    return keys.map(function (key) {
      return key + "=" + OAuthV2.encode(obj[key]);
    }).join("&");
  }

  return "";
};

/*
	Build the signature string from the object
*/

OAuthV2.buildSignatureString = function (method, url, parameters) {
  return [method.toUpperCase(), OAuthV2.encode(url) , OAuthV2.encode(parameters)].join("&");
};

/*
	Retuns encoded HMAC-SHA1 from key and text
*/
OAuthV2.signature = function (text, key) {
  crypto = require("crypto");
  return OAuthV2.encode(crypto.createHmac('sha1', key).update(text).digest('base64'));
};

OAuthV2.signRequest = function (request, OAuthV2_parameters, consumer_secret, auth_token_secret) {
  OAuthV2_parameters = OAuthV2_parameters || {};

  // Set default values
  if (!OAuthV2_parameters.OAuthV2_nonce) {
    OAuthV2_parameters.oauth_nonce = OAuthV2.nonce();
  }
  if (!OAuthV2_parameters.OAuthV2_timestamp) {
    OAuthV2_parameters.oauth_timestamp = Math.floor(new Date().getTime() / 1000);
  }
  if (!OAuthV2_parameters.OAuthV2_signature_method) {
    OAuthV2_parameters.oauth_signature_method = OAuthV2.signatureMethod;
  }
  if (!OAuthV2_parameters.OAuthV2_version) {
    OAuthV2_parameters.oauth_version = OAuthV2.version;
  }

  if (!auth_token_secret) {
    auth_token_secret = "";
  }
  // Force GET method if unset
  if (!request.method) {
    request.method = "GET";
  }

  // Collect  all the parameters in one signatureParameters object
  var signatureParams = {};
  var parametersToMerge = [request.params, request.body, OAuthV2_parameters];
  for (var i in parametersToMerge) {
    var parameters = parametersToMerge[i];
    for (var k in parameters) {
      signatureParams[k] = parameters[k];
    }
  }

  // Create a string based on the parameters
  var parameterString = OAuthV2.buildParameterString(signatureParams);

  // Build the signature string
  var urlHost = request.protocol + "//" + request.host + "" + request.path;
  
  

  var signatureString = OAuthV2.buildSignatureString(request.method, urlHost, parameterString);
  // Hash the signature string
  

  
  var signatureKey = [OAuthV2.encode(consumer_secret), OAuthV2.encode(auth_token_secret)].join("&");

  var signature = OAuthV2.signature(signatureString, signatureKey);

  // Set the signature in the params
  OAuthV2_parameters.oauth_signature = signature;
  if (!request.headers) {
    request.headers = {};
  }
  

  
  if (request.typeOAuth.toLowerCase() == 'head') {
	  // Set the authorization header
	  var signature = Object.keys(OAuthV2_parameters).sort().map(function (key) {
		  var value = OAuthV2_parameters[key];
		  return key + '="' + value + '"';
	  }).join(", ");

	  request.headers.Authorization = 'OAuth ' + signature;
  } 
  // Set the content type header
  request.headers["Content-Type"] = "application/x-www-form-urlencoded";
  return request;
};

module.exports = OAuthV2;
