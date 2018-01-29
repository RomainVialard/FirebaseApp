/*
FirebaseApp

Copyright (c) 2016 - 2018 Romain Vialard - Ludovic Lefebure - Spencer Easton - Jean-Rémi Delteil - Simon Debray

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
var FirebaseApp_ = {};

FirebaseApp_.base = function (base) {
  this.base = base;
};

// noinspection JSUnusedGlobalSymbols
/**
 * Retrieves a database by url
 *
 * @param  {string} url the database url
 * @param  {string} optSecret a Firebase app secret
 * @return {FirebaseApp_.base} the Database found at the given URL
 */
function getDatabaseByUrl(url, optSecret) {
  if (!optSecret) optSecret = '';
  
  return new FirebaseApp_.base({
    url: url,
    secret: optSecret
  });
}


var baseClass_ = FirebaseApp_.base.prototype;

/**
 * Generates an authorization token to firebase
 *
 * @param  {string} userEmail the email account of the user you want to authenticate
 * @param  {object} optAuthData keypairs of data to be associated to this user.
 * @param  {string} serviceAccountEmail the email of the service account used to generate this token
 * @param  {string} privateKey the private key of this service account
 * @return {object} the auth token granting access to firebase
 */
baseClass_.createAuthToken = function (userEmail, optAuthData, serviceAccountEmail, privateKey) {
  if (arguments.length > 2) { //more then two means they want to use a service account
    if (typeof arguments[1] === "string") { // no optional data
      this.base.serviceAccountEmail = arguments[1];
      this.base.privateKey = arguments[2];
      optAuthData = {};
    }
    else if (typeof arguments[1] === "object") { // optional data is present
      this.base.serviceAccountEmail = serviceAccountEmail;
      this.base.privateKey = privateKey;
    }
    return this.createAuthTokenFromServiceAccount_(userEmail, optAuthData);
  }
  else {
    return this.createLegacyAuthToken_(userEmail, optAuthData);
  }
};

/**
 * Generates an authorization token to Firebase
 *
 * @param  {string} userEmail the email account of the user you want to authenticate
 * @param  {object} optAuthData keypairs of data to be associated to this user.
 * @return {object} the auth token granting access to firebase
 */
baseClass_.createAuthTokenFromServiceAccount_ = function (userEmail, optAuthData) {
  if (!("serviceAccountEmail" in this.base) || !("privateKey" in this.base)) {
    throw Error("You must provide both the serviceEmailAccount and the privateKey to generate a token")
  }
  // Specific YAMM
  if (!optAuthData) {
    var tmp = userEmail.split('@');
    var username = tmp[0];
    var domain = tmp[1];
    optAuthData = {
      domain: domain.replace(/\./g, '-'),
      username: username.replace(/^0+/, '').replace(/\./g, '-'),
      emailAddress: userEmail
    }
  }
  
  var header = JSON.stringify({
    "typ": "JWT",
    "alg": "RS256"
  });
  header = Utilities.base64EncodeWebSafe(header);
  var now = Math.floor((new Date).getTime() / 1E3);
  var body = {
    "iss": this.base.serviceAccountEmail,
    "sub": this.base.serviceAccountEmail,
    "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    "iat": now,
    "exp": now + 3600,
    "uid": userEmail.replace(/[|&;$%@"<>()+,.]/g, ""),
    "claims": {}
  };
  
  if (optAuthData) {
    Object.keys(optAuthData).forEach(function (item) {
      body.claims[item] = optAuthData[item];
    });
  }
  body = JSON.stringify(body); //Stringified after adding optional auth data
  body = Utilities.base64Encode(body);
  var signature = Utilities.computeRsaSha256Signature(header + "." + body, this.base.privateKey);
  return header + "." + body + "." + Utilities.base64Encode(signature);
};

/**
 * Generates an authorization token to firebase
 *
 * @param  {string} userEmail the email account of the user you want to authenticate
 * @param  {object} optAuthData keypairs of data to be associated to this user.
 * @return {object} the auth token granting access to firebase
 */
baseClass_.createLegacyAuthToken_ = function (userEmail, optAuthData) {
  // Specific YAMM
  if (!optAuthData) {
    var tmp = userEmail.split('@');
    var username = tmp[0];
    var domain = tmp[1];
    optAuthData = {
      domain: domain.replace(/\./g, '-'),
      username: username.replace(/^0+/, '').replace(/\./g, '-'),
      emailAddress: userEmail
    }
  }
  var header = JSON.stringify({
    "typ": "JWT",
    "alg": "HS256"
  });
  header = Utilities.base64EncodeWebSafe(header);
  var payload = {
    "v": 0,
    "d": {
      "uid": userEmail.replace(/[|&;$%@"<>()+,.]/g, "")
    },
    // iat : 'issued at' in second
    "iat": Math.floor((new Date).getTime() / 1E3)
  };
  if (optAuthData) {
    Object.keys(optAuthData).forEach(function (item) {
      payload.d[item] = optAuthData[item];
    });
  }
  payload = JSON.stringify(payload); //Stringified after adding optional auth data
  payload = Utilities.base64EncodeWebSafe(payload);
  var hmac = Utilities.computeHmacSha256Signature(header + "." + payload, this.base.secret);
  return header + "." + payload + "." + Utilities.base64EncodeWebSafe(hmac);
};

/**
 * Returns the data at this path
 *
 * @param  {string} path the path where the data is stored
 * @param  {object} optQueryParameters a set of query parameters
 * @return {object} the data found at the given path
 */
baseClass_.getData = function (path, optQueryParameters) {
  return FirebaseApp_._buildRequest("get", this.base, path, null, optQueryParameters);
};

/**
 * Returns data in all specified paths
 *
 * @param  {Array} requests array of requests
 * @return {object} responses to each requests
 */
baseClass_.getAllData = function (requests) {
  var base = this.base;
  return FirebaseApp_._buildAllRequests(requests, base);
};

/**
 * Generates a new child location using a unique key
 *
 * @param  {string} path the path where to create a new child
 * @param  {object} data the data to be written at the generated location
 * @param  {object} optQueryParameters a set of query parameters
 * @return {string} the child name of the new data that was added
 */
baseClass_.pushData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("post", this.base, path, data, optQueryParameters);
};

/**
 * Write data at the specified path
 *
 * @param  {string} path the path where to write data
 * @param  {object} data the data to be written at the specified path
 * @param  {object} optQueryParameters a set of query parameters
 * @return {object} the data written
 */
baseClass_.setData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("put", this.base, path, data, optQueryParameters);
};

/**
 * Update specific children at the specified path without overwriting existing data
 *
 * @param  {string} path the path where to update data
 * @param  {object} data the children to overwrite
 * @param  {object} [optQueryParameters] a set of query parameters
 * @return {object} the data written
 */
baseClass_.updateData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("patch", this.base, path, data, optQueryParameters);
};

/**
 * Delete data at the specified path
 *
 * @param  {string} path the path where to delete data
 * @param  {object} optQueryParameters a set of query parameters
 * @return {null}
 */
baseClass_.removeData = function (path, optQueryParameters) {
  return FirebaseApp_._buildRequest("delete", this.base, path, null, optQueryParameters);
};


/**
 * Pre-build the request
 *
 * @param method {String} the type of the request made to Firebase
 * @param base {Object} base information of Firebase
 * @param path {String} path to the whished location of Firebase
 * @param data {*} data to insert in the location
 * @param optQueryParameters {Object} optional query parameter for the call
 *
 * @return {*}
 */
FirebaseApp_._buildRequest = function (method, base, path, data, optQueryParameters) {
  if (optQueryParameters && typeof optQueryParameters !== "object") {
    throw new Error("optQueryParameters must be an object");
  }
  
  if (!path) path = '';
  
  var params = {
        method: method,
        headers: {},
        muteHttpExceptions: true
      },
      url = base.url + path + ".json",
      authToken = base.secret;
  
  // Check if authentication done via OAuth 2 access token
  if (authToken !== "" && authToken.indexOf('ya29.') !== -1) {
    params.headers["Authorization"] = "Bearer " + authToken;
    authToken = "";
  }
  
  // Init query parameters
  optQueryParameters = optQueryParameters || {};
  
  // Add authToken if needed
  if(authToken !== "") optQueryParameters["auth"] = authToken;
  
  // Build parameters before adding them in the url
  var parameters = [];
  for (var key in optQueryParameters) {
    
    // Encode non boolean parameters (except whitelisted keys)
    if (!FirebaseApp_._keyWhiteList[key] && isNaN(optQueryParameters[key]) && typeof optQueryParameters[key] !== 'boolean') {
      optQueryParameters[key] = encodeURIComponent('"' + optQueryParameters[key] + '"');
    }
    
    parameters.push(key + "=" + optQueryParameters[key]);
  }
  
  // Add all parameters
  url += "?"+ parameters.join("&");
  
  // Add data in the request if there is some
  if (data || data === 0) params.payload = JSON.stringify(data);
  
  // Change parameters for PATCH method
  if (method === "patch") {
    params.headers["X-HTTP-Method-Override"] = "PATCH";
    params.method = "post";
  }
  
  // Exponential back-off is needed as server errors are more and more common on Firebase
  for (var n = 0; n < 6; n++) {
    var result = FirebaseApp_._sendRequest(url, params);
    
    if (!result) return;
    else if (!(result instanceof Error)) break;
    else {
      if (n === 5) throw result;
      
      Utilities.sleep((Math.pow(2, n) * 1000) + (Math.round(Math.random() * 1000)));
    }
  }
  
  if (method === "post" && JSON.parse(result)['name']) return JSON.parse(result)['name'];
  
  // Sometimes JSON.parse() fails with "Unexpected token: <"
  try {
    return JSON.parse(result);
  }
  catch (e) {
    throw new Error(result);
  }
};

/**
 * Send the request to Firebase
 *
 * @param url {String} url to call for in Firebase
 * @param params {Object} parameters of the call
 *
 * @returns {*}
 * @private
 */
FirebaseApp_._sendRequest = function (url, params) {
  // Added Try-catch as fetch method can fail even with muteHttpExceptions
  // Usually when it times out - ie: when Firebase is tacking too long to answer (more than 60s)
  try {
    var result = UrlFetchApp.fetch(url, params);
  }
  catch (e) {
    // in case of timeout, if we are writing data, assume firebase will eventually write
    // ie don't throw error and continue to work
    if (params.method === "post" || params.method === "put" || params.method === "delete") return;
    else return new Error("We're sorry, a server error occurred. Please wait a bit and try again.");
  }
  
  var responseCode = result.getResponseCode();
  
  // print=silent returns a 204 No Content on success
  if (responseCode === 204) return;
  
  // Avoid returning the Firebase app secret in case of error
  if (result.toString().indexOf('auth=') !== -1) {
    return new Error("We're sorry, a server error occurred. Please wait a bit and try again.");
  }
  
  if (responseCode === 400 || responseCode === 401 || responseCode === 500 || responseCode === 502) {
    if (result.toString().indexOf('error') !== -1) return new Error(JSON.parse(result).error);
    else return new Error("We're sorry, a server error occurred. Please wait a bit and try again.");
  }
  
  return result;
};

FirebaseApp_._keyWhiteList = {
  auth: true,
  shallow: true,
  print: true,
  limitToFirst: true,
  limitToLast: true
};

/**
 * Pre-build all Urls
 *
 * @param {Array.<string | {url: string, optQueryParameters: {}}>} requests
 * @param {Object} base information of the database
 *
 * @return {*}
 */
FirebaseApp_._buildAllRequests = function (requests, base) {
  var authToken = base.secret,
      finalRequests = [],
      url,
      headers = {};
  
  // Check if authentication done via OAuth 2 access token
  if (authToken !== "" && authToken.indexOf('ya29.') !== -1) {
    headers["Authorization"] = "Bearer " + authToken;
    authToken = "";
  }
  
  // Prepare all URLs requests
  for (var i = 0; i < requests.length; i++){
    
    // Transform string request in object
    if (typeof requests[i] === "string"){
      requests[i] = {
        url: requests[i],
        optQueryParameters: {}
      };
    }
    else {
      // Make sure that query parameters are init
      requests[i].optQueryParameters = requests[i].optQueryParameters || {};
    }
    
    url = base.url + requests[i].url + ".json";
    
    // Add authToken if needed
    if (authToken !== "") {
      requests[i].optQueryParameters["auth"] = authToken;
    }
    
    // Build parameters before adding them in the url
    var parameters = [];
    for (var key in requests[i].optQueryParameters) {
      
      // Encode non boolean parameters (except whitelisted keys)
      if (!FirebaseApp_._keyWhiteList[key] && isNaN(requests[i].optQueryParameters[key]) && typeof requests[i].optQueryParameters[key] !== 'boolean') {
        requests[i].optQueryParameters[key] = encodeURIComponent('"' + requests[i].optQueryParameters[key] + '"');
      }
      
      parameters.push(key + "=" + requests[i].optQueryParameters[key]);
    }
    
    // Add all parameters
    url += "?"+ parameters.join("&");
    
    // Store request
    finalRequests.push({url: url, headers: headers, muteHttpExceptions: true});
  }
  
  return FirebaseApp_._sendAllRequests(finalRequests, requests);
};

/**
 * Send all request using UrlFetchApp.fetchAll()
 *
 * @param {Object.<{url: string, headers: {}, muteHttpExceptions: boolean}>} finalRequests
 * @param {Object<{url: string, optQueryParameters: {}}>} originalsRequests location of each data
 *
 * @return {*}
 * @private
 */
FirebaseApp_._sendAllRequests = function (finalRequests, originalsRequests) {
  var dataArray = UrlFetchApp.fetchAll(finalRequests),
      data = {};
  
  // Store each response in an object with the respective Firebase path as key
  for (var i = 0; i < dataArray.length; i++){
    data[originalsRequests[i].url] = JSON.parse(dataArray[i]);
  }
  
  return data;
};
