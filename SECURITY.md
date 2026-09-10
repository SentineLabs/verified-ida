# Security policy

## Alpha status

This Verified IDA alpha is an internal evaluation release for authorized
reviewers. Do not report security issues in a public issue tracker or attach
malware, IDA databases, credentials, proprietary licenses, or analysis traces
to a public report. Contact the maintainer or sender through the existing
private research channel.

## Relevant issues

Please report failures involving:

- execution or network access by an analyzed artifact;
- escape from the IDA, IDAPython, extraction, or emulation sandbox;
- mutation of a clean source IDB or read-only review copy;
- a receipt claiming success when canonical IDA state differs;
- loss or false attribution of evidence, operations, revisions, or review
  dispositions;
- credentials, licenses, hidden reasoning, or malware being included in a
  source bundle; or
- unsafe path handling or component extraction outside the project boundary.

Include the package version or Git commit, operating system, Python and IDA
versions, the command used with secrets removed, and the smallest reproducible
artifact. Share malware only through an approved private transfer mechanism.

## Operating boundary

Use disposable project directories and static-analysis workers. IDA and
model-authored static extraction run without network access in the validated
Linux deployment. The harness does not launch samples or recovered payloads;
bounded instruction emulation is available for static reasoning. The source archive
contains no samples, IDBs, API credentials, or IDA license material.

Model-authored byte extractors receive only approved byte utilities and supplied
in-memory inputs. Their launcher environment is allowlisted and cleared again
inside bubblewrap. Before model code runs, a Linux seccomp allowlist denies new
file opens, networking, process creation/exec, and executable memory mappings.
File output is limited to preopened artifact/report descriptors and process
stdio. Missing seccomp support
fails closed; the Python validator alone is not a security boundary. Read-only
IDAPython uses a separate IDA sandbox and also receives a cleared environment;
it does not use the extractor's compute-only syscall policy.

Review copies require settled transactions. Recovery validates project ownership
before replacing or removing files. Discarded workers must be terminated before
IDA companion cleanup. These are tested guarantees within the supported OS,
SDK, and IDA configuration, not a claim of resistance to kernel or IDA exploits.
