var cognitoAuth = function () {
  const REFRESH_TOKEN_INTERVAL = 3000000;//ms

  var poolData = {
    UserPoolId: "",
    ClientId: ""
  };

  userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  AWS.config.update({
    accessKeyId: "",
    secretAccessKey: "",
    region: ""
  });

  getCookie = function (cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
      var c = ca[i].trim();
      if (c.indexOf(name) === 0)
        return c.substring(name.length, c.length);
    }
    return null;
  };

  return {
    ///authenticates a user using userid and password
    authenticateUser: function (userId, pwd, onSuccess, onFailure) {
      var authenticationData = {
        Username: userId,
        Password: pwd,
      };

      var userData = {
        Username: userId,
        Pool: userPool
      };

      var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
      var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess,
        onFailure,        
        newPasswordRequired: function (userAttributes, requiredAttributes) {
          // User was signed up by an admin and must provide new
          // password and required attributes, if any, to complete
          // authentication.

          // the api doesn't accept this field back
          delete userAttributes.email_verified;

          // Get these details and call
          cognitoUser.completeNewPasswordChallenge(pwd, null, this);
        }

      });
    },

    getUser: function () {
      var cognitoUser = userPool.getCurrentUser();

      if (cognitoUser != null) {
        cognitoUser.getSession(function (err, session) {
          if (err) {
            return;
          }
        });
      }
    },

    ///changes password for the logged in user
    changePassword: function (oldpwd, newPwd, onsuccess, onfailure) {
      var cognitoUser = userPool.getCurrentUser();
      if (cognitoUser != null) {
        cognitoUser.getSession(function (err, session) {
          if (err) {
            return;
          }
          //before calling the change password, cognito user object needs to load the session from local storeg
          //hence calling change password inside getsession. else it will fail complaining user is not authenticated 
          //since session data will not be available.
          cognitoUser.changePassword(oldpwd, newPwd, function (err, result) {
            response = {}
            if (err) {
              onfailure;
            }
            else {
              onsuccess;
            }
          });
        });
      }
    },

    ///signout !!!
    signOut: function () {
      var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
      var cognitoUser = userPool.getCurrentUser();
      cognitoUser.signOut();
    },

    ///creates new user in the iser pool . this is an admin function
    ///here email verification is not required as configured while creating the userpool
    //if you need to set any properties, those needs to be added in UserAttributes array with structure  -  {Name:"",Value:""}
    ///any custom attribute that you defined, should start with custom when adding
    registerUser: function (userName, password, email, name, jobtitle, callback) {
      var params = {
        UserPoolId: "",             /* required */
        Username: userName,         /* required */
        DesiredDeliveryMediums: [

        ],
        ForceAliasCreation: false,
        MessageAction: 'SUPPRESS',
        TemporaryPassword: password,
        UserAttributes: [
          {
            Name: 'email_verified', /* required */
            Value: 'false'
          },
          {
            Name: 'email', /* required */
            Value: email
          },
          {
            Name: 'name', /* required */
            Value: name
          },
          {
            Name: 'custom:jobtitle',
            Value: jobtitle
          }
        ]        
      };
      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      cognitoidentityserviceprovider.adminCreateUser(params, callback);
    },

    //
    resetPassword: function (userName, password, callback) {
      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      cognitoidentityserviceprovider.adminSetUserPassword({
        "Password": password,
        "Permanent": true,
        "Username": userName,
        "UserPoolId": ""
      }, callback);

    },

    AdminDeleteUser: function (userName, callback) {
      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      cognitoidentityserviceprovider.adminDeleteUser({
        UserPoolId: "",
        Username: userName
      }, callback);
    },

    refreshToken: function () {
      var refToken = getCookie('refresh_token')
      if (!refToken) {        
        return;
      }

      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      cognitoidentityserviceprovider.adminInitiateAuth({
        "AuthFlow": 'REFRESH_TOKEN_AUTH',
        "ClientId": "",
        "UserPoolId": "",
        "AuthParameters": {
          'REFRESH_TOKEN': refToken
        },
      }, function (err, response) {
        if (err) {
          setTimeout(cognitoAuth.refreshToken, 60000); //if refresh fails, do it again in 1 minute.
          return;
        }
          if (response.AuthenticationResult && response.AuthenticationResult.IdToken) {
            ///since identityToken is valid for an hr, refersh it beforeit expires.
          setTimeout(cognitoAuth.refreshToken, REFRESH_TOKEN_INTERVAL);
        }
      });
    },

    ///list users in user pool based on the searchfield and value.
    listUsers: function (searchValue, searchfield, onCompletion) {
      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      cognitoidentityserviceprovider.listUsers({
        "Filter": searchfield + " ^=\"" + searchValue.trim() + "\"",
        "Limit": 10,
        "UserPoolId": ""
      }, onCompletion)

    },

    ///updates user attributes 
    updateAttributes: function (username, attributesArray, callback) {
      var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18' });
      parameters = {
        "UserAttributes": attributesArray,
        "Username": username,
        "UserPoolId": ""
      };
      cognitoidentityserviceprovider.adminUpdateUserAttributes(parameters, callback);
    },
  }
}();
