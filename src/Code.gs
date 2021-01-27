/*
 FirebaseApp
 https://github.com/RomainVialard/FirebaseApp
 
 Copyright (c) 2016 - 2021 Romain Vialard - Ludovic Lefebure - Spencer Easton - Jean-Rémi Delteil - Simon Debray
 
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

/**
 * @typedef {Object} Base
 * @property {string} url
 * @property {string} [secret]
 * @property {string} [serviceAccountEmail]
 * @property {string} [privateKey]
 */

/**
 * @typedef {Object} FirebaseApp_.Base
 * @property {Base} base
 * @property {baseClass_.createAuthToken} [createAuthToken]
 * @property {baseClass_.getData} [getData]
 * @property {baseClass_.getAllData} [getAllData]
 * @property {baseClass_.pushData} [pushData]
 * @property {baseClass_.setData} [setData]
 * @property {baseClass_.updateData} [updateData]
 * @property {baseClass_.removeData} [removeData]
 * @property {baseClass_.getUrlFromPath} [getUrlFromPath]
 */

/**
 * @param {Base} base
 */
FirebaseApp_.Base = function (base) {
  this.base = base;
};

// noinspection JSUnusedGlobalSymbols
/**
 * Retrieves a database by url
 *
 * @param  {string} url - the database url
 * @param  {string} [optSecret] - a Firebase app secret
 *
 * @returns {FirebaseApp_.Base} the Database found at the given URL
 */
function getDatabaseByUrl(url, optSecret) {
  if (!new RegExp(".*/$").test(url)) url += "/";
  /** @type {Base} */
  var base = {
    url: url,
    secret: optSecret || '',
  };
  return new FirebaseApp_.Base(base);
}

/**
 * Returns a valid Firebase key from a given string
 * Firebase Keys can't contain any of the following characters: . $ # [ ] /
 * https://firebase.google.com/docs/database/usage/limits#data_tree
 * https://groups.google.com/forum/#!msg/firebase-talk/vtX8lfxxShk/skzA5vQFdosJ
 *
 * @param  {string} string - the string to encode
 *
 * @returns {string} the encoded string
 */
function encodeAsFirebaseKey(string) {
  return string.replace(/\%/g, '%25')
    .replace(/\./g, '%2E')
    .replace(/\#/g, '%23')
    .replace(/\$/g, '%24')
    .replace(/\//g, '%2F')
    .replace(/\[/g, '%5B')
    .replace(/\]/g, '%5D');
}

/**
 * Returns a decoded string from a Firebase key encoded by encodeAsFirebaseKey()
 *
 * @param  {string} string - the encoded Firebase key
 *
 * @returns {string} the decoded string
 */
function decodeFirebaseKey(string) {
  return string.replace(/\%25/g, '%')
    .replace(/\%2E/g, '.')
    .replace(/\%23/g, '#')
    .replace(/\%24/g, '$')
    .replace(/\%2F/g, '/')
    .replace(/\%5B/g, '[')
    .replace(/\%5D/g, ']');
}

/**
 * Signs in or signs up a user using credentials from an Identity Provider (IdP) - eg: google.com.
 * https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp
 * 
 *
 * @param  {object} firebaseConfig - see the "Get config object for your web app" section in the page linked below.
 *                                   https://support.google.com/firebase/answer/7015592?hl=en
 * @param  {string} idToken - an OpenID Connect identity token retrieved via ScriptApp.getIdentityToken()
 * @returns {object} the auth token granting access to firebase
 */
function signInWithIdp(firebaseConfig, idToken) {
  var url = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=' + firebaseConfig.apiKey;
  var options = {
    method: 'POST',
    payload: JSON.stringify({
      requestUri: 'https://' + firebaseConfig.authDomain,
      postBody: 'id_token=' + idToken + '&providerId=google.com',
      returnSecureToken: true,
      returnIdpCredential: true
    }),
    contentType: 'application/json'
  };
  // if the ErrorHandler library is loaded, use it (https://github.com/RomainVialard/ErrorHandler)
  if (typeof ErrorHandler !== 'undefined') {
    var res = ErrorHandler.urlFetchWithExpBackOff(url, options);
    if (res instanceof Error) {
      // for now return empty object in case of error
      return {};
    }
  }
  else {
    var res = UrlFetchApp.fetch(url, options);
  }
  var responseData = JSON.parse(res.getContentText());
  return responseData;
}

var baseClass_ = FirebaseApp_.Base.prototype;

/**
 * Generates an authorization token to firebase
 *
 * @param  {string} userEmail the email account of the user you want to authenticate
 * @param  {object} optAuthData key-pairs of data to be associated to this user.
 * @param  {string} serviceAccountEmail the email of the service account used to generate this token
 * @param  {string} privateKey the private key of this service account
 * @returns {object} the auth token granting access to firebase
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


FirebaseApp_._CustomClaimBlackList = {
  'iss': true,
  'sub': true,
  'aud': true,
  'exp': true,
  'iat': true,
  'auth_time': true,
  'nonce': true,
  'acr': true,
  'amr': true,
  'azp': true,

  'email': true,
  'email_verified': true,
  'phone_number	': true,
  'name': true,
  'firebase	': true,
};


/**
 * Generates an authorization token to Firebase
 *
 * @param  {string} userEmail - the email account of the user you want to authenticate
 * @param  {object} optCustomClaims - key-pairs of data to be associated to this user (aka custom claims).
 *
 * @returns {object} the auth token granting access to firebase
 */
baseClass_.createAuthTokenFromServiceAccount_ = function (userEmail, optCustomClaims) {
  if (!("serviceAccountEmail" in this.base) || !("privateKey" in this.base)) {
    throw Error("You must provide both the serviceEmailAccount and the privateKey to generate a token");
  }

  var header = JSON.stringify({
    "typ": "JWT",
    "alg": "RS256",
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
    "claims": {},
  };

  // Add custom claims if any
  optCustomClaims && Object.keys(optCustomClaims).forEach(function (item) {
    // Throw on invalid Custom Claims key (https://firebase.google.com/docs/auth/admin/custom-claims#set_and_validate_custom_user_claims_via_the_admin_sdk)
    if (FirebaseApp_._CustomClaimBlackList[item]) {
      throw new Error(FirebaseApp_.NORMALIZED_ERRORS.INVALID_CUSTOM_CLAIMS_KEY);
    }

    body.claims[item] = optCustomClaims[item];
  });

  // Check Custom Claims length
  if (JSON.stringify(body.claims).length > 1000) {
    throw new Error(FirebaseApp_.NORMALIZED_ERRORS.INVALID_CUSTOM_CLAIMS_LENGTH);
  }

  var stringifiedBody = JSON.stringify(body); // Stringified after adding optional auth data
  stringifiedBody = Utilities.base64Encode(stringifiedBody);
  var signature = Utilities.computeRsaSha256Signature(header + "." + stringifiedBody, this.base.privateKey);
  return header + "." + stringifiedBody + "." + Utilities.base64Encode(signature);
};

/**
 * Generates an authorization token to firebase
 *
 * @param  {string} userEmail the email account of the user you want to authenticate
 * @param  {object} optCustomClaims - key-pairs of data to be associated to this user (aka custom claims).
 * @returns {object} the auth token granting access to firebase
 */
baseClass_.createLegacyAuthToken_ = function (userEmail, optCustomClaims) {
  var header = JSON.stringify({
    "typ": "JWT",
    "alg": "HS256",
  });
  header = Utilities.base64EncodeWebSafe(header);
  var payload = {
    "v": 0,
    "d": {
      "uid": userEmail.replace(/[|&;$%@"<>()+,.]/g, ""),
    }, // iat : 'issued at' in second
    "iat": Math.floor((new Date).getTime() / 1E3),
  };
  if (optCustomClaims) {
    Object.keys(optCustomClaims).forEach(function (item) {
      payload.d[item] = optCustomClaims[item];
    });
  }
  var stringifiedPayload = JSON.stringify(payload); // Stringified after adding optional auth data
  stringifiedPayload = Utilities.base64EncodeWebSafe(stringifiedPayload);
  var hmac = Utilities.computeHmacSha256Signature(header + "." + stringifiedPayload, this.base.secret);
  return header + "." + stringifiedPayload + "." + Utilities.base64EncodeWebSafe(hmac);
};

/**
 * https://firebase.google.com/docs/reference/rest/database?hl=en#section-query-parameters
 * @typedef {Object} OptQueryParameters
 * @property {string} [auth]
 * @property {string} [shallow] - Set this to true to limit the depth of the data returned at a location.
 * @property {string} [print] - Formats the data returned in the response from the server.
 * @property {string} [limitToFirst]
 * @property {string} [limitToLast]
 */

/**
 * Returns the data at this path
 *
 * @param  {string} path - the path where the data is stored
 * @param  {OptQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @returns {object} the data found at the given path
 */
baseClass_.getData = function (path, optQueryParameters) {
  // Send request
  // noinspection JSAnnotator
  var [res] = FirebaseApp_._buildAllRequests([{
    method: 'get',
    path: path,
    optQueryParameters: optQueryParameters,
  },], this);

  // Throw error
  if (res instanceof Error) {
    throw res;
  }

  return res;
};

/**
 * Returns data in all specified paths
 *
 * @param  {Array.<string | FirebaseApp_.request>} requests - array of requests
 *
 * @returns {object} responses to each requests
 */
baseClass_.getAllData = function (requests) {
  return FirebaseApp_._buildAllRequests(requests, this);
};

/**
 * Generates a new child location using a unique key
 *
 * @param  {string} path - the path where to create a new child
 * @param  {object} data - the data to be written at the generated location
 * @param  {OptQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @returns {string} the child name of the new data that was added
 */
baseClass_.pushData = function (path, data, optQueryParameters) {
  // Send request
  // noinspection JSAnnotator
  var [res] = FirebaseApp_._buildAllRequests([{
    method: 'post',
    path: path,
    data: data,
    optQueryParameters: optQueryParameters,
  },], this);

  // Throw error
  if (res instanceof Error) {
    throw res;
  }

  return res;
};

/**
 * Write data at the specified path
 *
 * @param  {string} path - the path where to write data
 * @param  {object} data - the data to be written at the specified path
 * @param  {OptQueryParameters} [optQueryParameters] - a set of query parameters
 *
 * @returns {object} the data written
 */
baseClass_.setData = function (path, data, optQueryParameters) {
  // Send request
  // noinspection JSAnnotator
  var [res] = FirebaseApp_._buildAllRequests([{
    method: 'put',
    path: path,
    data: data,
    optQueryParameters: optQueryParameters,
  },], this);

  // Throw error
  if (res instanceof Error) {
    throw res;
  }

  return res;
};

/**
 * Update specific children at the specified path without overwriting existing data
 *
 * @param  {string} path - the path where to update data
 * @param  {object} data - the children to overwrite
 * @param  {OptQueryParameters} [optQueryParameters] a - set of query parameters
 *
 * @returns {object} the data written
 */
baseClass_.updateData = function (path, data, optQueryParameters) {
  // Send request
  // noinspection JSAnnotator
  var [res] = FirebaseApp_._buildAllRequests([{
    method: 'patch',
    path: path,
    data: data,
    optQueryParameters: optQueryParameters,
  },], this);

  // Throw error
  if (res instanceof Error) {
    throw res;
  }

  return res;
};

/**
 * Delete data at the specified path
 *
 * @param  {string} path - the path where to delete data
 * @param  {OptQueryParameters} [optQueryParameters] - a set of query parameters
 * 
 * @returns {null}
 */
baseClass_.removeData = function (path, optQueryParameters) {
  // Send request
  // noinspection JSAnnotator
  var [res] = FirebaseApp_._buildAllRequests([{
    method: 'delete',
    path: path,
    optQueryParameters: optQueryParameters,
  },], this);

  // Throw error
  if (res instanceof Error) {
    throw res;
  }

  return res;
};

/**
 * Gets the absolute URL from the specified path
 *
 * @param  {string} path - the path / location to convert to URL
 * @returns {string} an encoded URL that is ready to be put into a browser
 */
baseClass_.getUrlFromPath = function (path) {
  var url = this.base.url;
  var keysInPath = path.split('/');
  for (var i = 0; i < keysInPath.length; i++) {
    url += encodeURIComponent(FirebaseApp.encodeAsFirebaseKey(keysInPath[i])) + "/";
  }
  return url;
};

FirebaseApp_._keyWhiteList = {
  auth: true,
  shallow: true,
  print: true,
  limitToFirst: true,
  limitToLast: true,
};

FirebaseApp_._errorCodeList = {
  '400': true, // bad request
  // '401': true, // Unauthorized (we do not retry on this error, as this is sent on unauthorized access by the rules)
  '500': true, // Internal Server Error
  '502': true, // Bad Gateway
};

FirebaseApp_._methodWhiteList = {
  'post': true,
  'put': true,
  'delete': true,
};

/**
 * @typedef {string} FirebaseApp_.NORMALIZED_ERROR
 */

/**
 * List all known Errors
 */
FirebaseApp_.NORMALIZED_ERRORS = {
  TRY_AGAIN: "We're sorry, a server error occurred. Please wait a bit and try again.",
  GLOBAL_CRASH: "We're sorry, a server error occurred. Please wait a bit and try again.",
  PERMISSION_DENIED: "Permission denied",
  INVALID_DATA: "Invalid data; couldn't parse JSON object. Are you sending a JSON object with valid key names?",
  INVALID_DATA_BIS: "Invalid data; couldn't parse JSON object, array, or value.",
  INVALID_CUSTOM_CLAIMS_KEY: "Invalid custom claims key",
  INVALID_CUSTOM_CLAIMS_LENGTH: "Invalid custom claims length (>1000)",
  URLFETCHAPP_CRASH: "We're sorry, a server error occurred. Please wait a bit and try again.",
};


/**
 * List errors on which no retry is needed
 */
FirebaseApp_.NORETRY_ERRORS = {};
FirebaseApp_.NORETRY_ERRORS[FirebaseApp_.NORMALIZED_ERRORS.PERMISSION_DENIED] = true;
FirebaseApp_.NORETRY_ERRORS[FirebaseApp_.NORMALIZED_ERRORS.INVALID_DATA] = true;
FirebaseApp_.NORETRY_ERRORS[FirebaseApp_.NORMALIZED_ERRORS.INVALID_DATA_BIS] = true;
FirebaseApp_.NORETRY_ERRORS[FirebaseApp_.NORMALIZED_ERRORS.URLFETCHAPP_CRASH] = true;


// noinspection JSUnusedGlobalSymbols, ThisExpressionReferencesGlobalObjectJS
this['FirebaseApp'] = {
  // Add local alias to run the library as normal code
  getDatabaseByUrl: getDatabaseByUrl,
  encodeAsFirebaseKey: encodeAsFirebaseKey,
  decodeFirebaseKey: decodeFirebaseKey,
  signInWithIdp: signInWithIdp,

  NORMALIZED_ERRORS: FirebaseApp_.NORMALIZED_ERRORS,
};

/**
 * @typedef {Object} FirebaseApp_.request
 * @property {string} path
 * @property {'get' | 'post' | 'put' | 'patch' | 'delete'} [method]
 * @property {any} [data]
 * @property {OptQueryParameters} [optQueryParameters]
 * @property {Object} [response]
 * @property {Error} [error]
 */

/**
 * Pre-build all Urls
 *
 * @param {Array.<string | FirebaseApp_.request>} requests
 * @param {FirebaseApp_.Base} db information of the database
 *
 * @returns {Array.<Object | *>}
 */
FirebaseApp_._buildAllRequests = function (requests, db) {
  var authToken = db.base.secret,
    finalRequests = [],
    headers = {};

  // Deep copy of object to avoid changing it
  /** @type {Array.<FirebaseApp_.request>} */
  var initialRequests = JSON.parse(JSON.stringify(requests));

  // Check if authentication done via OAuth 2 access token
  if (authToken && authToken.indexOf('ya29.') !== -1) {
    headers['Authorization'] = 'Bearer ' + authToken;
    authToken = '';
  }

  // Prepare all URLs requests
  for (var i = 0; i < initialRequests.length; i++) {

    // Transform string request in object
    if (typeof initialRequests[i] === 'string') {
      initialRequests[i] = {
        optQueryParameters: {},
        path: initialRequests[i].toString(),
      };
    }
    else {
      // Make sure that query parameters are initialized
      initialRequests[i].optQueryParameters = initialRequests[i].optQueryParameters || {};
      initialRequests[i].path = initialRequests[i].path || '';
    }

    // Init request object
    var requestParam = {
      muteHttpExceptions: true,
      headers: {},
      url: '',
      method: initialRequests[i].method || 'get',
    };

    // Add data if any
    'data' in initialRequests[i] && (requestParam.payload = JSON.stringify(initialRequests[i].data));

    // Add Authorization header if necessary
    headers['Authorization'] && (requestParam.headers['Authorization'] = headers['Authorization']);

    // Change parameters for PATCH method
    if (requestParam.method === 'patch') {
      requestParam.headers['X-HTTP-Method-Override'] = 'PATCH';
      requestParam.method = 'post';
    }

    // Add authToken if needed
    authToken && (initialRequests[i].optQueryParameters['auth'] = authToken);

    // Query parameters in URLs aren't parsed correctly (and are not RFC-compliant, according to RFC 3986, Section 2).
    // To parse URLs in queries correctly, we need to add the X-Firebase-Decoding: 1 header to all REST requests.
    requestParam.headers['X-Firebase-Decoding'] = 1;
    // This workaround is temporary. An update expected in February 2019 will resolve issues with parsing URLs in query parameters.
    // Learn more: https://firebase.google.com/support/releases#november_12_2018

    // Build parameters before adding them in the url
    var parameters = [];
    for (var key in initialRequests[i].optQueryParameters) {

      // Encode non boolean parameters (except whitelisted keys)
      if (!FirebaseApp_._keyWhiteList[key] && typeof initialRequests[i].optQueryParameters[key] === 'string') {
        initialRequests[i].optQueryParameters[key] = encodeURIComponent('"' + initialRequests[i].optQueryParameters[key] + '"');
      }

      parameters.push(key + '=' + initialRequests[i].optQueryParameters[key]);
    }

    // Build request URL, encode all "%" to avoid URL path auto decoding
    requestParam.url = db.base.url + initialRequests[i].path.replace(/%/g, '%25').replace(/\+/g, '%2b') + '.json' + (parameters.length ? '?' + parameters.join('&') : '');

    // Store request
    finalRequests.push(requestParam);
  }


  // Get request results
  FirebaseApp_._sendAllRequests(finalRequests, initialRequests, db);
  var data = [];

  // Store each response in an object with the respective Firebase path as key
  for (var j = 0; j < initialRequests.length; j++) {
    data.push('response' in initialRequests[j] ? initialRequests[j].response : initialRequests[j].error);
  }

  return data;
};

/**
 * Send all request using UrlFetchApp.fetchAll()
 * The results are directly written in the originalsRequests objects (in the <error> and <response> fields
 *
 * @param {Array.<{url: string, headers: {}, muteHttpExceptions: boolean, method: string, data?: string, payload?: string}>} finalRequests
 * @param {Array<FirebaseApp_.request>} originalsRequests - location of each data
 * @param {FirebaseApp_.Base} db - information of the database
 * @param {number} [n] - exponential back-off count
 *
 * @returns {*}
 * @private
 */
FirebaseApp_._sendAllRequests = function (finalRequests, originalsRequests, db, n) {
  var responses;
  var failureOnUrlFetchApp = false;

  // If we only have one request, use fetch() instead of fetchAll(), as it's quicker
  if (finalRequests.length === 1) {

    // if the ErrorHandler library is loaded, use it (https://github.com/RomainVialard/ErrorHandler)
    if (typeof ErrorHandler !== 'undefined') {
      responses = [
        // if failure, usually ErrorHandler.NORMALIZED_ERRORS.SERVICE_INVOKED_TOO_MANY_TIMES_FOR_ONE_DAY
        // best to throw error
        ErrorHandler.urlFetchWithExpBackOff(finalRequests[0].url, finalRequests[0], {
          throwOnFailure: true,
          doNotLogKnownErrors: true,
        }),
      ];
    }
    else {
      try {
        responses = [
          UrlFetchApp.fetch(finalRequests[0].url, finalRequests[0]),
        ];
      }
      catch (e) {
        console.error('Error on UrlFetchApp');
        Logger.log(e);
        // Address unavailable | Địa chỉ không khả dụng | Unexpected error | DNS error
        failureOnUrlFetchApp = true;
      }
    }

    if (failureOnUrlFetchApp) {
      // If we are writing data, assume Firebase will eventually write -> ignore failure
      if (FirebaseApp_._methodWhiteList[finalRequests[0].method]) {
        responses = [
          new FirebaseApp_.FetchResponse(200, undefined),
        ];
      }
      else {
        responses = [
          new FirebaseApp_.FetchResponse(0, '{"error":"' + FirebaseApp_.NORMALIZED_ERRORS.URLFETCHAPP_CRASH + '"}'),
        ];
      }
    }
  }
  // For multiple request, use fetchAll()
  else {
    try {
      responses = UrlFetchApp.fetchAll(finalRequests);
    }
    catch (e) {
      // <e> will contain the problematic URL (only one) in clear, so with the secret if provided.
      // As we are not able to clearly tell which request crashed, and we will not retry with excluding request one by one
      throw new Error(FirebaseApp_.NORMALIZED_ERRORS.GLOBAL_CRASH);
    }
  }

  var errorCount = 0;
  // to push all requests that should be retried
  var retry = {
    finalReq: [],
    originalReq: [],
  };

  // Init exponential back-off counter
  n = n || 0;

  // Process all responses
  for (var i = 0; i < responses.length; i++) {
    var responseCode = responses[i].getResponseCode();

    // print=silent, used to improve write performance returns a 204 No Content on success
    // https://firebase.google.com/docs/database/rest/save-data#section-rest-write-performance
    if (responseCode === 204) {
      originalsRequests[i].response = undefined;

      // Delete possible previous error (when in re-try)
      delete originalsRequests[i].error;

      continue;
    }

    var responseContent = responses[i].getContentText();

    // if response content is a string and contains the Firebase secret, assume it's an error on which a retry is needed
    // and replace the error returned by a generic one to avoid throwing the secret
    if (db.base.secret && typeof responseContent === 'string' && responseContent.indexOf(db.base.secret) !== -1) {
      errorCount += 1;
      Logger.log(responseContent);
      originalsRequests[i].error = new Error(FirebaseApp_.NORMALIZED_ERRORS.TRY_AGAIN);

      retry.finalReq.push(finalRequests[i]);
      retry.originalReq.push(originalsRequests[i]);

      continue;
    }

    var errorMessage;
    var responseParsed;
    // try parsing response
    try {
      if (typeof HANDLE_FORBIDDEN_CHARS_IN_FIREBASE_KEYS !== 'undefined' && HANDLE_FORBIDDEN_CHARS_IN_FIREBASE_KEYS == true) {
        // If the global variable HANDLE_FORBIDDEN_CHARS_IN_FIREBASE_KEYS has been set to true
        // loop through all keys in the data retrieved from Firebase
        // and decode encoded Firebase Keys if we find any (via FirebaseApp.decodeFirebaseKey())
        //
        // WARNING: this is deactivated by default as looping through all keys might take a lot of time
        // (if the data retrieved from Firebase contains many keys)
        // in some tests, the exec time went from 1s to 60s after activating this option
        var keysToReplace = {};
        responseParsed = JSON.parse(responseContent, function (key, value) {
          // Alter the behavior of the parsing process to find keys to decode
          var encodedKey = FirebaseApp.decodeFirebaseKey(key);
          if (encodedKey != key) {
            keysToReplace[key] = encodedKey;
          }
          return value;
        });
        if (Object.keys(keysToReplace).length) {
          for (var encodedKey in keysToReplace) {
            // make sure we only replace Firebase Keys, not values
            var encodedKeyEscaped = encodedKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
            var encodedKeyRegExp = new RegExp('"' + encodedKeyEscaped + '":', 'g');
            responseContent = responseContent.replace(encodedKeyRegExp, '"' + keysToReplace[encodedKey] + '":');
          }
          responseParsed = JSON.parse(responseContent);
        }
      }
      else {
        responseParsed = JSON.parse(responseContent);
      }
    }
    catch (e) {
      Logger.log(e);
      // if responseContent is undefined => internal error on UrlFetch service, try again
      // It is caught as JSON.parse(undefined) fails ("Unexpected token")
      errorMessage = FirebaseApp_.NORMALIZED_ERRORS.TRY_AGAIN;
    }

    // Save valid response
    if (responseCode === 200 && !errorMessage) {

      // For POST request, the result is a JSON {"name": "$newKey"} and we want to return the $newKey
      if (finalRequests[i].method === 'post' && finalRequests[i].headers['X-HTTP-Method-Override'] !== 'PATCH') {
        originalsRequests[i].response = responseParsed && responseParsed['name'] || '';
      }
      else {
        originalsRequests[i].response = responseParsed;
      }

      // Delete possible previous error (when in re-try)
      delete originalsRequests[i].error;

      continue;
    }

    if (responseCode === 401) {
      originalsRequests[i].error = new Error(responseParsed.error || FirebaseApp_.NORMALIZED_ERRORS.PERMISSION_DENIED);

      continue;
    }

    if ((typeof HANDLE_FORBIDDEN_CHARS_IN_FIREBASE_KEYS !== 'undefined' && HANDLE_FORBIDDEN_CHARS_IN_FIREBASE_KEYS == true) &&
      responseCode === 400 &&
      responseParsed &&
      (responseParsed.error === FirebaseApp_.NORMALIZED_ERRORS.INVALID_DATA ||
        responseParsed.error === FirebaseApp_.NORMALIZED_ERRORS.INVALID_DATA_BIS)) {
      errorCount += 1;
      if (!originalsRequests[i].path) {
        // multi-location updates, avoid encoding paths "/"
        // https://firebase.googleblog.com/2015/09/introducing-multi-location-updates-and_86.html
        for (var pathAsKey in originalsRequests[i].data) {
          originalsRequests[i].data[pathAsKey] = FirebaseApp_._encodeAllKeys(originalsRequests[i].data[pathAsKey]);
        }
      }
      else {
        originalsRequests[i].data = FirebaseApp_._encodeAllKeys(originalsRequests[i].data);
      }
      finalRequests[i].payload = JSON.stringify(originalsRequests[i].data);

      retry.finalReq.push(finalRequests[i]);
      retry.originalReq.push(originalsRequests[i]);
      continue;
    }

    // Retry on specific response codes, specific error messages or if we failed to parse the response
    if ((errorMessage && errorMessage === FirebaseApp_.NORMALIZED_ERRORS.TRY_AGAIN) ||
      (FirebaseApp_._errorCodeList[responseCode] && !responseParsed) ||
      (FirebaseApp_._errorCodeList[responseCode] && responseParsed.error && !FirebaseApp_.NORETRY_ERRORS[responseParsed.error])) {
      errorCount += 1;
      // Add the response code to the error message if it comes from the response
      originalsRequests[i].error = responseParsed && responseParsed.error ?
        new Error(responseCode + ' - ' + responseParsed.error) :
        new Error(errorMessage || FirebaseApp_.NORMALIZED_ERRORS.TRY_AGAIN);

      retry.finalReq.push(finalRequests[i]);
      retry.originalReq.push(originalsRequests[i]);

      continue;
    }

    // All other cases are errors that we do not retry
    if (responseParsed && responseParsed.error) {
      originalsRequests[i].error = new Error(responseParsed.error);
    }
    else {
      originalsRequests[i].error = new Error(FirebaseApp_.NORMALIZED_ERRORS.TRY_AGAIN);
    }
  }

  // Retry at max 6 times on failed calls
  // and - for the first try - only retry if
  // there are less than 100 errors and the error number account for less than a quarter of the requests
  // This is to avoid emptying the UrlFetchApp quota for nothing
  // if there's only one request, we can retry
  if (errorCount &&
    n <= 6 &&
    (n > 0 || originalsRequests.length == 1 || (errorCount <= 100 && errorCount < originalsRequests.length / 4))) {
    // Exponential back-off is needed as server errors are more and more common on Firebase
    Utilities.sleep((Math.pow(2, n) * 1000) + (Math.round(Math.random() * 1000)));

    FirebaseApp_._sendAllRequests(retry.finalReq, retry.originalReq, db, n + 1);
  }
};

/**
 * Applies encodeAsFirebaseKey() on all keys of a given object
 *
 * @param  {object} object - the object on which all keys should be encoded
 *
 * @returns {object} the encoded object
 */
FirebaseApp_._encodeAllKeys = function (object) {
  var keysToReplace = {};
  object = JSON.stringify(object, function (key, value) {
    // Alter the behavior of the stringification process to find keys to encode
    var encodedKey = FirebaseApp.encodeAsFirebaseKey(key);
    if (encodedKey != key) {
      keysToReplace[key] = encodedKey;
    }
    return value;
  });
  for (var invalidKey in keysToReplace) {
    // make sure we only replace keys, not values
    var invalidKeyEscaped = invalidKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
    var invalidKeyRegExp = new RegExp('"' + invalidKeyEscaped + '":', 'g');
    object = object.replace(invalidKeyRegExp, '"' + keysToReplace[invalidKey] + '":');
  }
  return JSON.parse(object);
}

/**
 * Fake UrlFetchApp.HTTPResponse object
 *
 * @param {number} responseCode
 * @param {string | undefined} responseContent
 *
 * @constructor
 */
FirebaseApp_.FetchResponse = function (responseCode, responseContent) {
  this.code = responseCode;
  this.content = responseContent;
};

/**
 * Return set HTTP response code
 *
 * @returns {number}
 */
FirebaseApp_.FetchResponse.prototype.getResponseCode = function () {
  return this.code;
};

/**
 * Return set HTTP response content text
 *
 * @returns {string | undefined}
 */
FirebaseApp_.FetchResponse.prototype.getContentText = function () {
  return this.content;
};