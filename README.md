
# FirebaseApp
The Google Apps Script binding for the Firebase Realtime Database

# Install
Best it to copy the content of this file in your Google Apps Script project:
https://github.com/RomainVialard/FirebaseApp/blob/master/src/Code.gs

You can also add it as a library, though this is not recommended.  
https://developers.google.com/apps-script/guides/libraries  
Library's script ID: **1VlYLzhwx0YEoxIe62eItLAZeobVt_l-GQUKt2MXXuBHFVsqBkl9C_yBB**


# Documentation / Reference

## Class FirebaseApp

## `getDatabaseByUrl(url, optSecret)`

Retrieves a database by url

 * **Parameters:**
   * `url` — `string` — - the database url
   * `[optSecret]` — `string` — - a Firebase app secret

     <p>
 * **Returns:** `Database` — the Database found at the given URL


## `encodeAsFirebaseKey(string)`

Returns a valid Firebase key from a given string Firebase Keys can't contain any of the following characters: . $ # [ ] / https://firebase.google.com/docs/database/usage/limits#data_tree https://groups.google.com/forum/#!msg/firebase-talk/vtX8lfxxShk/skzA5vQFdosJ

 * **Parameters:** `string` — `string` — - the string to encode

     <p>
 * **Returns:** `string` — the encoded string

## `decodeFirebaseKey(string)`

Returns a decoded string from a Firebase key encoded by encodeAsFirebaseKey()

 * **Parameters:** `string` — `string` — - the encoded Firebase key

     <p>
 * **Returns:** `string` — the decoded string

## `signInWithIdp(firebaseConfig, idToken)`

Signs in or signs up a user using credentials from an Identity Provider (IdP) - eg: google.com. https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp

 * **Parameters:**
   * `firebaseConfig` — `object` — - see the "Get config object for your web app" section in the page linked below.

     https://support.google.com/firebase/answer/7015592?hl=en
   * `idToken` — `string` — - an OpenID Connect identity token retrieved via ScriptApp.getIdentityToken()
 * **Returns:** `object` — the auth token granting access to firebase

## Class Database
## `createAuthToken(userEmail, optAuthData, serviceAccountEmail, privateKey)`

Generates an authorization token to firebase

 * **Parameters:**
   * `userEmail` — `string` — the email account of the user you want to authenticate
   * `optAuthData` — `object` — key-pairs of data to be associated to this user.
   * `serviceAccountEmail` — `string` — the email of the service account used to generate this token
   * `privateKey` — `string` — the private key of this service account
 * **Returns:** `object` — the auth token granting access to firebase

## `createAuthTokenFromServiceAccount(userEmail, optCustomClaims)`

Generates an authorization token to Firebase

 * **Parameters:**
   * `userEmail` — `string` — - the email account of the user you want to authenticate
   * `optCustomClaims` — `object` — - key-pairs of data to be associated to this user (aka custom claims).

     <p>
 * **Returns:** `object` — the auth token granting access to firebase

## `createLegacyAuthToken(userEmail, optCustomClaims)`

Generates an authorization token to firebase

 * **Parameters:**
   * `userEmail` — `string` — the email account of the user you want to authenticate
   * `optCustomClaims` — `object` — - key-pairs of data to be associated to this user (aka custom claims).
 * **Returns:** `object` — the auth token granting access to firebase

## `getData(path, optQueryParameters)`

Returns the data at this path

 * **Parameters:**
   * `path` — `string` — - the path where the data is stored
   * `[optQueryParameters]` — `OptQueryParameters` — - a set of query parameters

     <p>
 * **Returns:** `object` — the data found at the given path

## `getAllData(requests)`

Returns data in all specified paths

 * **Parameters:** `{Array.<string` — FirebaseApp_.request>} requests - array of requests

     <p>
 * **Returns:** `object` — responses to each requests

## `pushData(path, data, optQueryParameters)`

Generates a new child location using a unique key

 * **Parameters:**
   * `path` — `string` — - the path where to create a new child
   * `data` — `object` — - the data to be written at the generated location
   * `[optQueryParameters]` — `OptQueryParameters` — - a set of query parameters

     <p>
 * **Returns:** `string` — the child name of the new data that was added

## `setData(path, data, optQueryParameters)`

Write data at the specified path

 * **Parameters:**
   * `path` — `string` — - the path where to write data
   * `data` — `object` — - the data to be written at the specified path
   * `[optQueryParameters]` — `OptQueryParameters` — - a set of query parameters

     <p>
 * **Returns:** `object` — the data written

## `updateData(path, data, optQueryParameters)`

Update specific children at the specified path without overwriting existing data

 * **Parameters:**
   * `path` — `string` — - the path where to update data
   * `data` — `object` — - the children to overwrite
   * `[optQueryParameters]` — `OptQueryParameters` — a - set of query parameters

     <p>
 * **Returns:** `object` — the data written

## `removeData(path, optQueryParameters)`

Delete data at the specified path

 * **Parameters:**
   * `path` — `string` — - the path where to delete data
   * `[optQueryParameters]` — `OptQueryParameters` — - a set of query parameters

     <p>
 * **Returns:** `null` — 

## `getUrlFromPath(path)`

Gets the absolute URL from the specified path

 * **Parameters:** `path` — `string` — - the path / location to convert to URL
 * **Returns:** `string` — an encoded URL that is ready to be put into a browser

#Tutorials
https://sites.google.com/site/scriptsexamples/new-connectors-to-google-services/firebase/tutorials
