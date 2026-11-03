# Changelog

## 2026-11-03

- Rechecked published parent indicators and approved 23 explicit hosts already within reported wildcard coverage: 211 unique domains, 159 after compression.
- Refresh lists and discovery daily through PRs to main, with explicit CI dispatch and automatic merge after required checks pass.
- Distinguish partial discovery (exit 3, warning and report) from invalid arguments or unexpected script errors (workflow failure).
- Update setup-python to 7.1.0; verify checkout 7.0.1 and upload-artifact 7.0.2 pins; check and group action updates daily through Dependabot.
- Automatically merge validated non-draft same-repository PRs, including Dependabot, without executing PR code in the privileged merge workflow.

## 2026-10-19

- Reviewed Citizen Lab Appendix C and Confiant's published Indicators section.
- Added six explicit Citizen Lab hosts: 188 unique domains, 159 after compression.
- Clarified partial coverage, historical indicators, associated sites and client update behavior.
- Added root records alongside asterisk wildcard records and distinguished rule/domain counts.
- Reject unknown or conflicting categories and empty builds; check generated output without modifying files.
- Added offline regression tests, pull request CI, bounded discovery with a time share per service, and explicit partial/error reports.
- Added contributor guidance, source attribution, issue templates and separate code/list licensing scope.

## 2026-10-16

- Initial compilation: 182 unique domains, 154 after compression.
- Added five list variants across eight formats, source files and discovery/build scripts.
