# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
  - Support for task signals. `nomad alloc signal` is now working.
  - Bind task directories into started containers.
  - Added CHANGELOG to project.
  - Support for command execution inside tasks. `nomad alloc exec` is now
    working in containers started with the `boot` parameter.
### Changed
  - Naming of started containers now matches the schema of the docker driver
    `<task-name>-<allocID>`.

## [0.0.1] - 2020-01-12
Initial release. A minimal implementation to be able to run containers with
`systemd-nspawn`

### Added
  - Start/stop/recover tasks is working.
  - Small subset of possible `systemd-nspawn` arguments configurable.
  - Private networking enabled by default.
  - Port forwarding is working the same way as in docker driver.
  - Stats monitoring.
  - Enforce memory limits on started containers.
  - Example config and job files.
  - README with argument reference.

