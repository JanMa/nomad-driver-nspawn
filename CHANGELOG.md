# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
  - Support for new `memory_max` setting
### Changed
  - Update to Nomad v1.1.0
  - Lower log level of passed arguments to systemd-nspawn to DEBUG

## [0.6.0] - 2021-01-19
### Added
  - Support for group level network stanza
### Fixed
  - Ensure tests are always built on code changes
  - Run "apt update" in Actions pipeline
### Changed
  - Adjust Nginx example to use group network stanza
  - Update to Nomad v1.0.2

## [0.5.0] - 2021-01-07
### Added
  - Support for running containers without private networking.
  - Support for running multiple containers in the same network-zone.
  - GitHub Actions CI pipeline for automated builds and tests
### Fixed
  - Ensure all test resources are cleaned up.

## [0.4.1] - 2020-10-29
### Fixed
  - Ensure all test containers are properly stopped.
  - Fixed a bug which caused tasks to not be recovered on Nomad restarts (#17)

## [0.4.0] - 2020-10-03
### Added
  - Support for granting additional capabilities to containers. @mateuszlewko
  - Support for all new options of `resolv_conf` added in Systemd 246. @mateuszlewko
  - Ensure images can be safely downloaded in parallel.
  - Ported tests from `exec` driver to this project. They cover basic
    functionality like starting, stopping, killing, destroying tasks and
    executing commands in them.
  - Added Makefile for common build operations.
### Changed
  - Improved error message if systemd-nspawn fails to start a task.
  - `NewNspawnDriver()` now returns a driver with the default config settings.
### Fixed
  - Fixed a runtime panic which occurred if a task had no resources assigned.

## [0.3.0] - 2020-08-12
### Added
  - Support for Nomad `bridge` networking mode. This also enables the use of
    Consul Connect.
  - Output the error why systemd-nspawn fails on startup. It is added to the
    logs and shown in the WebUi.
  - Support for `volume_mount` stanza. Volumes are enabled by default and can be
    disabled by setting `volumes = false` inside the driver config.

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

