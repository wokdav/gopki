# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2023-03-09
### Added
- Add certificate manipulations.
- Added serial number and uids to cert config.

### Changed
- Added changelog.
- Added some small benchmarks.
- Minor cert example doc change.

## [0.1.0] - 2023-03-04
### Added
- Admission extension now works.

### Fixed
- Skip tests for cross-platform deterministism.
- Incremented go version again for workflow.
- Updated github workflow to new go version.
- Fixed ecdsa fork.

### Changed
- Added some small benchmarks.
- Minor cert example doc change.
- Fixed formatting for generated go files.

## [0.0.1] - 2023-03-01
### BREAKING CHANGE
- refactor to allow config hashing. optional/override are now on a different indent

### Added
- crypto operations are now deterministic (not yet across platforms).
- re-generate certificate, if issuer changes
- existing keys are now reused
- reduced go version requirement to what the source code actually reflects
- generation upon expiration option now works
- Added small logging package
- added logging argument plus some logs
- add simple log handling
- log certificate summary on info
- actually make use of the promised !null feature
- added policy qualifiers to certpolicies extension
- higher error tolerance for unrecognized files
- added comma escaping for distinguished names

### Fixed
- fixed wrong test expectation
- re-worked extension merging to work regardless of ordering; internal examples now build; removed outdated test
- Filesystem is more stable.
- fixed errWriter being nil by default.
- fixed some bugs in example files
- removed code duplication in GeneratePrivateKey
- custom subject attribute oids work in profiles now, too

### Changed
- Create codeql.yml.
- smarter error reports when configs don't match; removed useless code
- refactored database interface
- actually use db interface; better names for update strats
- tests now don't write into the filesystem
- renamed project to github url
- add github workflow
- initial commit

[Unreleased]: https://github.com/wokdav/gopki/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/wokdav/gopki/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/wokdav/gopki/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/wokdav/gopki/releases/tag/v0.0.1
