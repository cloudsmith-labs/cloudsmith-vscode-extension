# Repository lifecycle rendering fixture

Test-only companion extension. Install separately beside the attested production
VSIX in a disposable, credential-free VS Code profile. Open `fixture.code-workspace`
and expand **Repository lifecycle fixture** in the Explorer sidebar.

The companion requires production modules from the installed Cloudsmith extension.
It composes the real transport, pagination, adapter, repository node, provider, and
Inspect command. Only the external HTTP response and account/credential boundary
are synthetic and confined to the companion instances. No network request,
SecretStorage access, credential bootstrap, or production global override occurs.

The processing record is contract-derived from the pinned official Cloudsmith API
schema, not an observed customer response. Processing remains active until
**Lifecycle fixture: Complete processing** is invoked. The same permanent package
identifier then returns completed scan evidence. Refreshing while processing does
not advance the state. Inspect uses the current row and opens the real sanitized
package inspection document. The transport summary reports only fixture request
categories and counts.

This proves a rendered fixture TreeView with installed production modules. It does
not prove authenticated production activation or live Cloudsmith behavior. The
production package allowlist excludes this directory and the companion must never
be included in its VSIX.
