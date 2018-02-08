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

FirebaseApp_.Base = function (base) {
  /**
   * @type {{
   *   url: string
   *   [secret]: string
   *   [serviceAccountEmail]: string
   *   [privateKey]: string
   * }}
   */
  this.base = base;
};

// noinspection JSUnusedGlobalSymbols
/**
 * Retrieves a database by url
 *
 * @param  {string} url - the database url
 * @param  {string} [optSecret] - a Firebase app secret
 *
 * @return {FirebaseApp_.Base} the Database found at the given URL
 */
function getDatabaseByUrl(url, optSecret) {
  return new FirebaseApp_.Base({
    url: url,
    secret: optSecret || ''
  });
}


var baseClass_ = FirebaseApp_.Base.prototype;

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
 * @typedef {{
 *   [auth]: string
 *   [shallow]: string
 *   [print]: string
 *   [limitToFirst]: string
 *   [limitToLast]: string
 * }} optQueryParameters
 */

/**
 * Returns the data at this path
 *
 * @param  {string} path - the path where the data is stored
 * @param  {optQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @return {object} the data found at the given path
 */
baseClass_.getData = function (path, optQueryParameters) {
  return FirebaseApp_._buildRequest("get", this.base, path, null, optQueryParameters);
};

/**
 * Returns data in all specified paths
 *
 * @param  {Array.<string | {url: string, [optQueryParameters]: optQueryParameters}>} requests - array of requests
 *
 * @return {object} responses to each requests
 */
baseClass_.getAllData = function (requests) {
  return FirebaseApp_._buildAllRequests(requests, this);
};

/**
 * Generates a new child location using a unique key
 *
 * @param  {string} path - the path where to create a new child
 * @param  {object} data - the data to be written at the generated location
 * @param  {optQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @return {string} the child name of the new data that was added
 */
baseClass_.pushData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("post", this.base, path, data, optQueryParameters);
};

/**
 * Write data at the specified path
 *
 * @param  {string} path - the path where to write data
 * @param  {object} data - the data to be written at the specified path
 * @param  {optQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @return {object} the data written
 */
baseClass_.setData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("put", this.base, path, data, optQueryParameters);
};

/**
 * Update specific children at the specified path without overwriting existing data
 *
 * @param  {string} path - the path where to update data
 * @param  {object} data - the children to overwrite
 * @param  {optQueryParameters} [optQueryParameters] a - set of query parameters
 *
 * @return {object} the data written
 */
baseClass_.updateData = function (path, data, optQueryParameters) {
  return FirebaseApp_._buildRequest("patch", this.base, path, data, optQueryParameters);
};

/**
 * Delete data at the specified path
 *
 * @param  {string} path - the path where to delete data
 * @param  {optQueryParameters} [optQueryParameters] - a set of query parameters
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
 * @param path {String} path to the wished location of Firebase
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
  if (authToken !== "") optQueryParameters["auth"] = authToken;
  
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
  
  // Sometimes JSON.parse() fails with "Unexpected token: <" -> because the content returned is an HTML error screen
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
    if (result.toString().indexOf('error') !== -1) return new Error(JSON.parse(result.getContentText()).error);
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
FirebaseApp_._errorCodeList = {
  '400': true, // bad request
  // '401': true, // Unauthorized (we do not retry on this error, as this is sent on unauthorized access by the rules)
  '500': true, // Internal Server Error
  '502': true // Bad Gateway
};
FirebaseApp_._methodWhiteList = {
  'post': true,
  'put': true,
  'delete': true
};
FirebaseApp_._ERROR_TRY_AGAIN = 'We\'re sorry, a server error occurred. Please wait a bit and try again.';
FirebaseApp_._ERROR_GLOBAL_CRASH = 'We\'re sorry, a server error occurred. Please wait a bit and try again.';

/**
 * @typedef {{
 *   path: string
 *   [method]: 'get' | 'post' | 'put' | 'patch' | 'delete'
 *   [data]: *
 *   optQueryParameters: optQueryParameters
 *   
 *   [response]: Object
 *   [error]: Error
 * }} FirebaseApp_.request
 */


/**
 * Pre-build all Urls
 *
 * @param {Array.<string | FirebaseApp_.request>} requests
 * @param {FirebaseApp_.Base} db information of the database
 *
 * @return {*}
 */
FirebaseApp_._buildAllRequests = function (requests, db) {
  var authToken = db.base.secret,
      finalRequests = [],
      headers = {};
  
  // Check if authentication done via OAuth 2 access token
  if (authToken && authToken.indexOf('ya29.') !== -1) {
    headers['Authorization'] = 'Bearer ' + authToken;
    authToken = '';
  }
  
  // Prepare all URLs requests
  for (var i = 0; i < requests.length; i++){
    
    // Transform string request in object
    if (typeof requests[i] === 'string'){
      requests[i] = {
        optQueryParameters: {},
        path: requests[i]
      };
    }
    else {
      // Make sure that query parameters are initialized
      requests[i].optQueryParameters = requests[i].optQueryParameters || {};
      requests[i].path = requests[i].path || '';
    }
    
    // Init request object
    var requestParam = {
      muteHttpExceptions: true,
      headers: {},
      url: '',
      method: requests[i].method || 'get'
    };
    
    // Add data if any
    'data' in requests[i] && (requestParam.payload = JSON.stringify(requests[i].data));
    
    // Add Authorization header if necessary
    headers['Authorization'] && (requestParam.headers['Authorization'] = headers['Authorization']);
    
    // Change parameters for PATCH method
    if (requestParam.method === 'patch') {
      requestParam.headers['X-HTTP-Method-Override'] = 'PATCH';
      requestParam.method = 'post';
    }
    
    // Add authToken if needed
    authToken && (requests[i].optQueryParameters['auth'] = authToken);
    
    
    // Build parameters before adding them in the url
    var parameters = [];
    for (var key in requests[i].optQueryParameters) {
      
      // Encode non boolean parameters (except whitelisted keys)
      if (!FirebaseApp_._keyWhiteList[key] && isNaN(requests[i].optQueryParameters[key]) && typeof requests[i].optQueryParameters[key] !== 'boolean') {
        requests[i].optQueryParameters[key] = encodeURIComponent('"'+ requests[i].optQueryParameters[key] +'"');
      }
      
      parameters.push(key +'='+ requests[i].optQueryParameters[key]);
    }
    
    // Build request URL
    requestParam.url = db.base.url + requests[i].path + '.json'+ (parameters.length ? parameters.join('&') : '');
    
    // Store request
    finalRequests.push(requestParam);
  }
  
  
  // Get request results
  FirebaseApp_._sendAllRequests(finalRequests, requests, db);
  var data = {};
  
  // Store each response in an object with the respective Firebase path as key
  for (var j = 0; j < requests.length; j++){
    data[requests[j].path] = 'response' in requests[j]
      ? requests[j].response
      : requests[j].error;
  }
  
  return data;
};

/**
 * Send all request using UrlFetchApp.fetchAll()
 * The results are directly written in the originalsRequests objects (in the <error> and <response> fields
 *
 * @param {Array.<{url: string, headers: {}, muteHttpExceptions: boolean, method: string, [data]: string}>} finalRequests
 * @param {Array<FirebaseApp_.request>} originalsRequests - location of each data
 * @param {FirebaseApp_.Base} db - information of the database
 * @param {number} [n] - exponential back-off count
 *
 * @return {*}
 * @private
 */
FirebaseApp_._sendAllRequests = function (finalRequests, originalsRequests, db, n) {
  var responses;
  
  // If we only have one request, use fetch() instead of fetchAll(), as it's quicker
  if (finalRequests.length === 1){
    try {
      responses = [
        UrlFetchApp.fetch(finalRequests[0].url, finalRequests[0])
      ];
    }
    catch(e){
      // In case of timeout, if we are writing data, assume firebase will eventually write -> ignore return value
      if (FirebaseApp_._methodWhiteList[ finalRequests[0].method ]){
        responses = [
          new FirebaseApp_.FetchResponse(200, undefined)
        ];
      }
      else{
        responses = [
          new FirebaseApp_.FetchResponse(400, 'Bad request or Time-out')
        ]
      }
    }
  }
  // For multiple request, use fetchAll()
  else{
    try {
      responses = UrlFetchApp.fetchAll(finalRequests);
    }
    catch(e){
      // <e> will contain the problematic URL (only one) in clear, so with the secret if provided.
      // As we are not able to clearly tell which request crashed, and we will not retry with excluding request one by one
      throw new Error(FirebaseApp_._ERROR_GLOBAL_CRASH);
    }
  }
  
  var errorCount = 0;
  var retry = {
    finalReq: [],
    originalReq: []
  };
  
  // Init exponential back-off counter
  n = n || 0;
  
  // Process all responses
  for (var i = 0; i < responses.length; i++){
    var responseCode = responses[i].getResponseCode();
    
    // print=silent returns a 204 No Content on success
    if (responseCode === 204){
      originalsRequests[i].response = undefined;
      
      // Delete possible previous error (when in re-try)
      delete originalsRequests[i].error;
      
      continue;
    }
    
    var responseContent = responses[i].getContentText();
    
    // Avoid returning the Firebase app secret in case of error
    if (responseContent.indexOf(db.base.secret) !== -1){
      errorCount += 1;
      
      originalsRequests[i].error = new Error(FirebaseApp_._ERROR_TRY_AGAIN);
      
      retry.finalReq.push(finalRequests[i]);
      retry.originalReq.push(originalsRequests[i]);
      
      continue;
    }
    
    
    // try parsing response
    var errorMessage;
    var responseParsed;
    try{
      responseParsed = JSON.parse(responseContent);
    }
    catch(e){
      errorMessage = FirebaseApp_._ERROR_TRY_AGAIN;
    }
    
    // Process possible errors and retry
    if (FirebaseApp_._errorCodeList[responseCode] || errorMessage) {
      errorCount += 1;
      
      originalsRequests[i].error = new Error(responseParsed.error || FirebaseApp_._ERROR_TRY_AGAIN);
      
      retry.finalReq.push(finalRequests[i]);
      retry.originalReq.push(originalsRequests[i]);
      
      continue;
    }
    
    // Save valid response
    if (responseCode === 200){
      
      // For POST request, the result is a JSON {"name": "$newKey"} and we want to return the $newKey
      if (finalRequests[i].method === 'post' && finalRequests[i].headers['X-HTTP-Method-Override'] !== 'PATCH'){
        originalsRequests[i].response = responseParsed['name'];
      }
      else{
        originalsRequests[i].response = responseParsed;
      }
      
      // Delete possible previous error (when in re-try)
      delete originalsRequests[i].error;
      
      continue;
    }
    
    // All other cases are errors that we do not retry
    originalsRequests[i].error = new Error(FirebaseApp_._ERROR_TRY_AGAIN);
  }
  
  // Retry the errors, 6 times maximum,
  // and for the first try only retry if
  // there are less than 100 errors and the error number account for less than a quarter of the requests
  if (errorCount && n <= 6 && (n > 0 || (errorCount <= 100 && errorCount < originalsRequests.length / 4))){
    // Exponential back-off is needed as server errors are more and more common on Firebase
    Utilities.sleep((Math.pow(2, n) * 1000) + (Math.round(Math.random() * 1000)));
    
    FirebaseApp_._sendAllRequests(retry.finalReq, retry.originalReq, db, n+1);
  }
};


/**
 * Fake UrlFetchApp.HTTPResponse object
 *
 * @param {number} responseCode
 * @param {string | undefined} responseContent
 *
 * @constructor
 */
FirebaseApp_.FetchResponse = function(responseCode, responseContent){
  this.code = responseCode;
  this.content = responseContent;
};

/**
 * Return set HTTP response code
 *
 * @return {number}
 */
FirebaseApp_.FetchResponse.prototype.getResponseCode = function () {
  return this.code;
};

/**
 * Return set HTTP response content text
 *
 * @return {string | undefined}
 */
FirebaseApp_.FetchResponse.prototype.getContentText = function () {
  return this.content;
};

