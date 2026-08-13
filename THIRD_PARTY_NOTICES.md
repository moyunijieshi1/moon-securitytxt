# Third-Party Notices

## RFC 9116 (security.txt)

This project reuses the `Contact`, `Encryption`, `Acknowledgments` and
`Expires` example lines from Appendix A.1 of RFC 9116
("A File Format to Aid the Security Vulnerability Disclosure Process",
E. Foudil, Y. Shafranovich, April 2022) as a test fixture
(`test_validator.mbt`). The fixture reproduces the published example
verbatim, including its known errata: the `Expires` value uses a
lower-case `z` and the second `Contact` value lacks a URI scheme.

RFC 9116 is Copyright (c) 2022 IETF Trust and the persons identified as
the document authors, and is provided under the IETF Trust Legal
Provisions Relating to IETF Documents
(https://trustee.ietf.org/license-info). The excerpt is used for
conformance testing of an implementation of that specification.

## MoonBit Standard Library

The library depends only on the MoonBit standard library
(`moonbitlang/core`), which is licensed under the Apache License,
Version 2.0, Copyright International Digital Economy Academy.
