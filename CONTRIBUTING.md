To contribute code to this project, please open a branch labeled:

`<type>/<addition>`

Type can be any one of:

- feature
- bugfix
- compliance
- optimization

Addition should name the feature.

Examples:

- feature/secp384r1
- optimization/secp256r1
- etc

**No change may alter advertised protocol capabilities, negotiation behavior, trust semantics, crypto policy, or standards compliance without being explicitly called out in the PR description. A PR that contains an RFC-breaking change without explicit justification will be rejected, justifications require discussion.** _Yes, this project does deviate from RFC in a handful of places, but they are platform-specific and often hardware capability or memory pressure related._

To enforce this