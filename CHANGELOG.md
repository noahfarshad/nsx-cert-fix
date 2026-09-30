# Changelog

All notable changes to this project are documented here.

## [1.0.0] — 2026-09-30

### Added

- Initial public release. Plan by default. With --commit, replace the API certificate on each NSX Manager node and then the cluster VIP. Optional deletion of named edges whose deployment failed. CSR export and CA-signed import are the path when a self-signed certificate is not acceptable.

### Notes

- Example hostnames are nsx.example.com. Edge names in the help text are edge01 and edge02.
- The password comes from NSX_PASSWORD or a prompt. Nothing secret is printed.
- Certificate verification is off on these calls because the certificate being replaced is the one that would have been checked.
