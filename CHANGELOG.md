# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased
<!-- Add new, unreleased changes here. -->
* none

## [1.2.1] - in GAS v28 - 2018-03-19
* Errors on simple Firebase functions will now throw
* Encode "%" in URL path to avoid auto-decoding
* Remove YAMM specific custom claims for legacy auth token authentication

## [1.2.0] - in GAS v28 - 2018-03-08
* Added new method encodeAsFirebaseKey()
* Remove YAMM specific custom claims, check custom Claims validity

## [1.1.0] - in GAS v27 - 2018-02-15
* Added batch calls with urlFetchAll()