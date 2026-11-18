# LANE 9 report: HIRS

## 1. Upstream contribution rules

- CONTRIBUTING.md: no CLA and no DCO. Opening a PR means agreeing to a copyright waiver (Apache 2.0).
- SECURITY.md (added 2026-11-04): report vulnerabilities privately through the Security tab ("Report a
  vulnerability"), never in a public issue or PR. A person must review each report. Describe impact accurately.
- In practice this is a closed internal team. Of the last 400 PRs, none from a drive-by outsider was merged.
  On #1356 (ML-DSA algorithm agility) the maintainer wrote that they "aren't taking outside implementations"
  and asked for no draft PR.
- PRs go to `main` or `development`. CI (`hirs_unit_tests.yml`) runs on PRs to both.

## 2. Branches

| Branch | Base | Bound for | Commit |
|---|---|---|---|
| `fix/tcg-rim-tool-leftovers` | upstream/main `ec50382c` | issue first, then maybe a PR | `46f565bf` Remove tcg_rim_tool leftovers after its move to RIM-Tool |
| `lane/pqc-mldsa` | `fix/tcg-rim-tool-leftovers` | fork only | ML-DSA COSE engine, tests, fork CI workflow, this report |

### A: `fix/tcg-rim-tool-leftovers` (one squashed commit)

#1305 removed `tools/tcg_rim_tool`, but some references to it were left behind:

- `package/win/tcg-rim-tool/`: this is the Windows "hirstools" bundle that `hirs_package_linux.yml` copies into
  `artifacts/win/hirstools`. It still shipped `rim.ps1`, set a `rim` alias, and ran
  `Expand-Archive ..\tcg_rim_tool.zip`, but that zip is no longer built. The bundle also carries the
  **event log tool**, so deleting the directory outright would have broken the `cp` in the package workflow and
  dropped the Windows eventlog launcher. Instead I renamed it with `git mv` to `package/win/hirstools`, which
  matches the artifact folder, updated that one `cp` line, and stripped only the RIM pieces. Those are
  `rim.ps1`, the alias, the rim banner text, the rim unzip, and the rim section of the bundle README, which now
  points to nsacyber/RIM-Tool. I also fixed `eventLog.ps1`'s header comment, which was copy-pasted from the
  RIM script. CRLF endings in the two `.ps1` files that had them are preserved.
- `tools/scripts/eventcheck.sh`: deleted. Its first step is `java -jar ../tcg_rim_tool/build/libs/...`, so it
  cannot work any more. `git grep` found no references to the script.
- `README.md:103`: dropped tcg_rim_tool from the "require Java 25" note.
- `.gitignore`: dropped the 3-line `# tcg_rim_tool files` block.
- `.github/workflows/hirs_unit_tests.yml`: dropped the `mkdir` for `upload_reports/HIRS_ProvisionerTPM2`
  (removed in #866) and `upload_reports/tcg_rim_tool`. Nothing writes to either directory.

Deliberately left alone:
- The ~26 `HIRS_ProvisionerTPM2/*` lines in `.gitignore` are older #866 debris, outside this scope.
- `docs/HIRS_TCG_RIM_Tool_Users_Guide_3.0.pdf` and mentions inside the other PDFs. These are binary docs;
  whether to remove them is the maintainers' call.

### B: `lane/pqc-mldsa` (fork only)

ML-DSA (FIPS 204) signing and verification for **COSE_Sign1**, which is the signature format HIRS uses for TCG
Component RIMs (CoSWID) and CoRIMs (`hirs.utils.signature.cose.CoseSignature`, `CoRimBuilder`). It is all in
one place, HIRS_Utils, and isolated from the existing RSA and ECDSA paths:

- `CoseAlgorithm`: adds the IANA COSE registrations ML-DSA-44 = -48, ML-DSA-65 = -49 and ML-DSA-87 = -50
  (RFC 9964, checked against iana.org/assignments/cose on 2026-11-17). Also adds `isMlDsa(int)` and
  `isMlDsaName(String)`. These are additions only: `isRsa` and `isEcdsa` are untouched, and existing name/ID
  lookups return the same values as before.
- New `hirs.utils.crypto.MlDsaCrypto implements CryptoEngine`. It uses the JDK's **built-in** ML-DSA (JEP 497,
  JDK 25 Temurin). There is no new dependency, which fits the maintainers' "established, widely reviewed crypto
  providers" policy from #1356. It works as follows:
  - Loads PKCS #8 PEM keys. The parameter set is taken from the key, and a mismatched certificate or algorithm
    name is rejected.
  - Signs and verifies raw ML-DSA signatures. ML-DSA has no DER wrapping, so the signature goes straight into
    the COSE signature field.
  - Rejects a key or header of a different parameter set: `verify` returns false. The JDK throws on a
    wrong-length signature, and `verify` maps that to false.
  - `DefaultCrypto` is **not modified**. Callers choose `MlDsaCrypto` explicitly.
- `MlDsaCryptoTest` (6 tests), each run for ML-DSA-44, -65 and -87:
  - Checks the registry IDs.
  - Generates keys and checks that each key reports its parameter set.
  - Builds a COSE_Sign1 with `CoseSignature`, signs it, encodes it, and parses it back with
    `getToBeVerified`. The test then checks that alg -48/-49/-50 survives the parser and that the signature
    sizes are 2420/3309/4627 bytes (FIPS 204), then verifies the result. A tampered copy fails.
  - Parameter-set mismatch.
  - PKCS #8 PEM load from disk.
  - Embedded signing certificate (RFC 9360 x5chain and x5t): an ML-DSA-65 self-signed cert is built with
    BouncyCastle, re-parsed by the JDK, and `getEmbeddedCert` recovers it and validates the thumbprint. The kid
    comes from the Subject Key Identifier, and the signature verifies against the recovered cert.
  - JDK and BouncyCastle 1.86 cross-verification in both directions, using keys exchanged as SPKI.
- `.github/workflows/fork_mldsa_tests.yml`: fork-only workflow. On a push to `lane/pqc-mldsa` it runs
  `:HIRS_Utils:test --tests 'hirs.utils.crypto.*' --tests 'hirs.utils.signature.cose.*'` plus checkstyle on
  Temurin 25. Upstream's workflows trigger only on `pull_request`, so the branch push starts nothing else.

Honest scope notes:
- Supports only "pure" ML-DSA with an empty context, which is the COSE profile. There is no HashML-DSA, no
  composite or hybrid signatures, and no ACA/portal wiring.
- The ACA's credential issuance (`CertificateRequestProcessorService.getSignatureAlgorithm`) is untouched.
  That is the roadmap work upstream declined to take from outsiders (#1356, closed 2026-11) and is tracking
  internally (#1309 is open for ML-DSA PKI keygen).
- No NIST ACVP vectors are included. The tests prove HIRS's COSE path carries ML-DSA correctly, not that the
  JDK's FIPS 204 implementation conforms.

## 3. Evidence

Workflow lint for A (actionlint 1.7.7 plus PyYAML). The one finding is pre-existing and identical on
upstream/main. Only its line number moved, by the 2 deleted lines:
```
$ actionlint -shellcheck= -oneline <upstream/main copies>
.github/workflows/hirs_unit_tests.yml:85:15: the runner of "actions/github-script@v6" action is too old ...
$ actionlint -shellcheck= -oneline .github/workflows/hirs_unit_tests.yml .github/workflows/hirs_package_linux.yml
.github/workflows/hirs_unit_tests.yml:83:15: the runner of "actions/github-script@v6" action is too old ...
yaml ok
$ git grep -n -I "tcg_rim_tool\|tcg-rim-tool\|eventcheck\|rim\.ps1\|HIRS_ProvisionerTPM2" -- ':!.gitignore'
(no output)
```

B was built in a WSL copy (`~/build/HIRS`) with Temurin 25.0.5 and Gradle 9.3.1 (wrapper):
```
$ ./gradlew --no-daemon -Dorg.gradle.jvmargs=-Xmx2g --max-workers=2 \
    :HIRS_Utils:test :HIRS_Utils:checkstyleMain :HIRS_Utils:checkstyleTest :HIRS_Utils:spotbugsMain
> Task :HIRS_Utils:test
> Task :HIRS_Utils:spotbugsMain
BUILD SUCCESSFUL in 1m 18s
HIRS_Utils test results: tests 101 skipped 0 fail 0   (95 pre-existing + 6 new)
testLoadPemPrivateKey(Path)      0.128s
testCoseSign1RoundTrip()         0.148s
testParameterSetMismatch()       0.006s
testEmbeddedMlDsaCertificate()   0.642s
testBouncyCastleInterop()        0.093s
testParameterSets()              0.005s
```
SpotBugs reported no findings in `MlDsaCrypto` or `CoseAlgorithm`. The first run caught a real bug:
`verify` let the JDK's `SignatureException` escape for a wrong-length signature. It is now mapped to `false`.

After fixing three checkstyle warnings in the test (magic numbers, a missing `@param`), the final local run
was checkstyle-clean:
```
$ ./gradlew ... :HIRS_Utils:test :HIRS_Utils:checkstyleMain :HIRS_Utils:checkstyleTest
BUILD SUCCESSFUL in 45s      (no [ant:checkstyle] warnings)
```
Fork CI (`fork_mldsa_tests.yml`, ubuntu-latest, Temurin 25) on commit `87eb6d39`: **success**,
https://github.com/Dukotah/HIRS/actions/runs/44246850046
```
HIRS_Utils_crypto_tests  Run HIRS_Utils crypto and COSE tests  BUILD SUCCESSFUL in 57s
```

## 4. Competing work check

- `gh pr list -R nsacyber/HIRS --state all -L 50`: no PRs from the spray accounts (theyottaboy, rudycelekli,
  arpitjain099, arthurianresolve, ravisastryk, r3vpwnx), checked at start and before finishing.
- `gh search prs "tcg_rim_tool"`: only #1305 itself and older checkstyle PRs. No PR or issue covers the
  leftovers.
- ML-DSA: #1356 (closed, outside implementations declined), #1268 (closed, PQC credential support),
  #1309 (open, internal: ML-DSA PKI keygen). Upstream has no COSE/RIM ML-DSA work in a PR, which is why B is
  scoped to COSE and stays fork-only.
- #1352 is already fixed by #1357; it only needs a maintainer to close it.

## 5. Draft upstream text (issue only; the owner decides whether to file it)

**Title:** Leftover tcg_rim_tool references after #1305

**Body:**
> #1305 moved the RIM tool to nsacyber/RIM-Tool, but a few references to it are still in this repo:
>
> - `package/win/tcg-rim-tool/` (copied into the ZIP_Files artifact by `hirs_package_linux.yml`) still ships
>   `rim.ps1`, sets a `rim` alias in `hirsshell.ps1`, and `create_hirstools_desktop_shortcut.ps1` runs
>   `Expand-Archive ..\tcg_rim_tool.zip`, which is no longer produced. The event log parts of that bundle still
>   apply.
> - `tools/scripts/eventcheck.sh` line 68 runs `../tcg_rim_tool/build/libs/tools/tcg_rim_tool-1.0.jar`.
> - `README.md` line 103 lists tcg_rim_tool among the packages that need Java 25.
> - `.gitignore` still has a `# tcg_rim_tool files` block.
> - `.github/workflows/hirs_unit_tests.yml` lines 27 and 29 create `upload_reports/HIRS_ProvisionerTPM2`
>   (removed in #866) and `upload_reports/tcg_rim_tool`, which nothing writes to.
>
> I have a small change that keeps the Windows bundle for the event log tool, renamed to
> `package/win/hirstools`. It removes the RIM pieces and `eventcheck.sh` and cleans up the lines above.
> I'm happy to open it as a PR if that's useful, or you may prefer to fold it into your own cleanup.

No upstream text for B: the maintainers asked for no PR on ML-DSA (#1356).

Owner-only note (do not post anywhere public): the `ProvisionUtils.parseTPMQuoteHash` input-length issue is a
known private security item (#1336, closed). This lane did not touch it, and nothing on the fork mentions it.

## 6. Land probability and next steps

- **A: Low-Med.** It finishes their own #1305/#866 cleanup and is tiny, but no drive-by outsider PR has merged
  in 400 PRs. The likely outcome, as with paccor #150, is that they make the change themselves after the issue.
  Owner: file the issue text above (human-reviewed), then offer the branch as a PR only if invited.
- **B: none upstream (by design).** It is a fork showcase. Owner: keep it on the fork. If it is ever mentioned
  upstream, link to it only in reply to an invitation, given #1356.
