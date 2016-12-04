# parse-server-wordpress-login
This module allows to register users of installations of Wordpress in Parse-Server for authDataManager

Include these files in the authDataManager directory of parse-server "parse-server/lib/authDataManager" and modify your "index.js" the directory "authDataManager" with the following:

var wordpress = require("./wordpress");

var providers = {
  facebook: facebook,
  instagram: instagram,
  ...
  ...
    wordpress: wordpress
};


En your "index.js" de your parse-server include the option "oauth" in your middleware.
var api = new ParseServer(
{ 
  ...
  ...
  oauth: {
   ...
   ...
   wordpress: [
			{
				url: "http://yourWordpressURL",	// REQUIRED		
				consumer_key: "lkbPsEotBkGn", // REQUIRED
				consumer_secret: "QpLPurXFWAbciQag4hE02EWc3jXVvh5DiWySN0hnVgE97vWF" // REQUIRED
			}
		]

  }
}
);



