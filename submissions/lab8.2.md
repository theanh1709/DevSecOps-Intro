# Lab 8.2 — Submission

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop",
      "digest": {
        "sha256": "<IMAGE_DIGEST_FROM_COSIGN_VERIFY_OUTPUT>"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:2514c182-b866-463b-9563-ac8569f312f6",
    "version": 1,
    "metadata": {
      "component": {
        "bom-ref": "73ec537d8d158676",
        "type": "container",
        "name": "bkimminich/juice-shop",
        "version": "v20.0.0"
      }
    },
    "components": [
      {
        "author": "Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias Küsel (https://github.com/mathiask88/)",
        "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
```
- Component count matches Lab 4 source: yes, 2 SBOM have 3,069 components.
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty diff = success

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `"https://localhost/lab8-student"`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?