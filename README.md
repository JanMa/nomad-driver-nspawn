# Nomad Systemd-Nspawn driver

This is a task driver for Hashicorp [Nomad](https://nomadproject.io) to run
containers with `systemd-nspawn`. **It is currently in active development and
not ready to be used yet!**

## TODO
- [x] Support for images
- [x] Port forwarding
- [x] IPTables rules
- [x] Improve task config
- [ ] download images
- [ ] support network modes
- [x] support volumes
- [x] support env vars
- [ ] support exec commands
- [ ] bind task directories in container
- [ ] enforce resource limits
