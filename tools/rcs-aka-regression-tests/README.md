# EAP-AKA challenge regression tests

Follow-up to Opstic's Constellation implementation, base
`b7d91f0a7a63fe135baba63bd9d092548b7b823c` (microg/GmsCore PR #3359).

The TS.43 caller builds EAP_ID with the carrier-supplied realm but the service
previously rebuilt a default-realm identity for key derivation. The patch passes
the exact advertised EAP_ID into the service, fixing the custom-realm response
MAC mismatch. A new differential test reproduces that mismatch.

The original EapAkaService parses RAND/AUTN then stops reading attributes. It
constructs a successful response without checking the request's AT_MAC.
This change parses the full framed challenge and verifies HMAC-SHA1-128 before
a successful AKA response. It keeps the synchronization-failure path, which
cannot derive K_aut, and validates the lengths of SIM response fields.

RFC 4187 sections 7, 9.3 and 10.15 define the mandatory challenge attributes
and MAC calculation. RFC 3748 section 4.1 defines EAP Length and link padding.

## Reproduction

Use Java 17+ and these Maven Central artifacts in one compiler directory:
- org.jetbrains.kotlin:kotlin-compiler-embeddable:1.9.24
- org.jetbrains.kotlin:kotlin-stdlib:1.9.24
- org.jetbrains.kotlin:kotlin-script-runtime:1.9.24
- org.jetbrains.kotlin:kotlin-reflect:1.6.10
- org.jetbrains.kotlin:kotlin-daemon-embeddable:1.9.24
- org.jetbrains.intellij.deps:trove4j:1.0.20200330
- org.jetbrains:annotations:13.0

```sh
python3 tools/rcs-aka-regression-tests/run.py --compiler-dir /path/to/compiler-jars
```

The runner compiles the actual service and unchanged PRF source, not a port of
those algorithms. TelephonyManager, Base64, logging and annotation dependencies
are small local adapters. Every identity, SIM result and challenge is synthetic.
There are no carrier requests, real subscriber secrets or device changes.

The same 16 scenarios yielded 5 pass / 11 fail on the original service and
16 pass / 0 fail on the patch. Controls validate a correctly signed request
and response, alternate attribute order, unknown skippable attributes, EAP
padding, and synchronization failure. Negative cases cover invalid/missing
MACs, duplicate attributes, bad lengths, non-skippable attributes, altered
headers, invalid Base64, and malformed SIM keys.

These are JVM-level service tests. Android instrumentation, full APK builds,
SIM/carrier interoperability, and locked-bootloader RCS send/receive have NOT
been validated by this contribution. It does not replace or claim authorship
of the existing RCS implementation, and it is not a completed bounty claim.
