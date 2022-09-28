# Tasks
## Dependency management
Docs: https://go.dev/ref/mod
1. Update `nomad` dependency to latest version `v1.3.5`
    - Tidy dependencies
    - Vendor new dependency
    - Rebuild project
2. Retract first published version of the driver
3. Replace `github.com/shirou/gopsutil` with `github.com/hashicorp/gopsutil` `v0.0.0-20180427102116-62d5761ddb7d`
    - Tidy dependencies
    - Vendor new dependency
    - Rebuild project
## Static binaries
1. Add `make` target for `linux/arm64`
## Finding documentation
1. Find out valid parameters for `executor.ExecCommand`
     - Change relevant code to put the process started by it into it's own cgroup.
     - Optional: Change if tests are still passing
