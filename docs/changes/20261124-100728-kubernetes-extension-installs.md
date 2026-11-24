### Fixed
- Extensions can now be installed on Kubernetes with the shipped manifests. The ConfigMap now sets `core.modules` to the writable config volume, where before every install failed writing beside the read-only configuration file.
