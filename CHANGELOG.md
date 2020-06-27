# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2020-06-27
### Added
  - Support for downloading images via the
    [`systemd-importd`](https://www.freedesktop.org/wiki/Software/systemd/importd/)
    API.
  - Example for downloading images.
  - Use built-in Nomad executor plugin to manage tasks.
### Fixed
  - Stats monitoring of running tasks. CPU and memory usage is now displayed
    correctly.

## [0.1.0] - 2020-03-04
### Added
  - Support for task signals. `nomad alloc signal` is now working.
  - Bind task directories into started containers.
  - Added CHANGELOG to project.
  - Support for command execution inside tasks. `nomad alloc exec` is now
    working in containers started with the `boot` parameter.
  - Validate configuration before trying to start a task. The driver will
    not try to start tasks with invalid configuration.
### Changed
  - Naming of started containers now matches the schema of the docker driver
    `<task-name>-<allocID>`.
### Fixed
  - Fixed argument parsing for `volatile` and `console` options.

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

