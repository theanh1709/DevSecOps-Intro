# Lab 4.2 — Submission

## Task 1: Trivy Comparison

### Side-by-side counts

| Severity  | Grype | Trivy |   Δ |
| --------- | ----: | ----: | --: |
| Critical  |    12 |    10 |  -2 |
| High      |    70 |    58 | -12 |
| Medium    |    11 |    55 |  44 |
| Low       |    55 |    23 | -32 |
| **Total** |   148 |   146 |  -2 |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:

1. CVE ID + tool that found it + tool that missed it

```text
CVE-2026-56848
Found by: Grype
Missed by: Trivy
```

2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?

(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

```text
Mostly different package matching rules. Grype identified the standalone Node.js binary and created a CPE-like match: cpe:2.3:a:nodejs:node.js:24.15.0.... Trivy’s report only shows /nodejs/bin/node as the image entrypoint metadata, not as a vulnerable package record.
```

### When would you pick each?
2-3 sentences each:

- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)

```text
Syft + Grype:
I would pick Syft+Grype when I want the SBOM to be a reusable artifact/attestation, not just an intermediate scan result. Syft can generate and store/sign the SBOM once, then Grype or other tools can scan that same SBOM later as vulnerability databases change, which is useful for supply-chain evidence, audits, and Lab 8-style provenance/attestation workflows.
Trivy:
I would pick Trivy when I want a simpler CI setup with one tool and one scan command. Trivy is convenient because it can scan images, filesystems, dependencies, IaC, secrets, and misconfigurations in one workflow, so it works well when the goal is broad coverage with less pipeline complexity.
```

## Task 2: GitHub Actions SBOM + SCA Pipeline

### Workflow file
Paste the full content of `.github/workflows/lab4-sbom-sca.yml`:

```yaml
name: Lab 4 - SBOM and SCA

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

env:
  IMAGE: bkimminich/juice-shop:v20.0.0
  REPORT_DIR: labs/lab4/reports

jobs:
  sbom-and-sca:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Create report directory
        run: mkdir -p "${REPORT_DIR}"

      - name: Pull container image
        run: docker pull "${IMAGE}"

      - name: Generate CycloneDX SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.IMAGE }}
          format: cyclonedx-json
          output-file: labs/lab4/reports/juice-shop.cdx.json
          upload-artifact: false

      - name: Generate SPDX SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.IMAGE }}
          format: spdx-json
          output-file: labs/lab4/reports/juice-shop.spdx.json
          upload-artifact: false

      - name: Scan SBOM with Grype
        uses: anchore/scan-action@v7
        with:
          sbom: labs/lab4/reports/juice-shop.cdx.json
          output-format: json
          output-file: labs/lab4/reports/grype-report.json
          fail-build: false

      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: image
          image-ref: ${{ env.IMAGE }}
          scanners: vuln
          severity: LOW,MEDIUM,HIGH,CRITICAL
          format: json
          output: labs/lab4/reports/trivy-report.json
          exit-code: "0"

      - name: Upload security reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: lab4-sbom-sca-reports
          path: labs/lab4/reports/
          retention-days: 30
```

### Successful workflow run
- Direct link to a **green (Success)** workflow run: [Github workflow](https://github.com/theanh1709/DevSecOps-Intro/actions/runs/32267164637/job/96114367266#logs)

### Job step explanation
Explain the purpose of each part of the `sbom-and-sca` job (2-3 sentences each):

## runs-on: ubuntu-latest

This job runs on a GitHub-hosted Ubuntu runner. Ubuntu is suitable here because Docker and the security scanning tools used by the workflow are well supported in this environment.

## Checkout repository

This step checks out the repository source code into the runner workspace. It is needed so the workflow can access the labs/lab4/reports path and save generated SBOM and scan report files into the repository directory structure.

## Create report directory

This step creates the output directory defined by REPORT_DIR. It ensures the later SBOM and vulnerability scan steps have a valid location to write their JSON report files.

## Pull container image

This step pulls the target containe image bkimminich/juice-shop:v20.0.0 before analysis begins. Pulling the image verifies that the image is available and prepares it for SBOM generation and vulnerability scanning.

## Generate CycloneDX SBOM with Syft

This step uses Syft through Anchore’s SBOM action to generate a CycloneDX-format SBOM for the Juice Shop image. The result is saved as juice-shop.cdx.json, which can be consumed by tools such as Grype for vulnerability analysis.

## Generate SPDX SBOM with Syft

This step generates a second SBOM for the same image, but in SPDX JSON format. Producing both CycloneDX and SPDX helps compare common SBOM standards and supports tools or organizations that prefer one format over the other.

## Scan SBOM with Grype

This step scans the CycloneDX SBOM using Grype to identify known vulnerabilities in the components listed in the SBOM. fail-build: false means the workflow records the findings but does not fail the pipeline because vulnerabilities are found.

## Scan image with Trivy

This step scans the container image directly with Trivy for vulnerabilities across LOW, MEDIUM, HIGH, and CRITICAL severities. The scan result is written to trivy-report.json, and exit-code: "0" ensures the workflow continues even if vulnerabilities are detected.

## Upload security reports

This step uploads all generated SBOM and vulnerability reports as a GitHub Actions artifact. The if: always() condition ensures the reports are uploaded even if an earlier step fails, and the artifact is retained for 30 days.

#### Triggers (`on:`)
What events start this workflow, and why run SBOM + SCA on both `push` and `pull_request`?

```text
This workflow starts on pull_request targeting main, push to main, and manual runs through workflow_dispatch. Running SBOM + SCA on pull requests helps detect dependency and image vulnerabilities before changes are merged, while running on push verifies the final state of main and preserves reports for the merged code path.
```

#### Job: `sbom-and-sca` / `runs-on: ubuntu-latest`
What is this job, and why does it run on a GitHub-hosted Ubuntu runner?

```text
The sbom-and-sca job is the CI job that pulls the target image, generates SBOM files, scans for vulnerabilities, and uploads the results. It runs on a GitHub-hosted Ubuntu runner because Ubuntu runners support Docker and common security scanning actions without requiring a self-hosted machine.
```

#### Step: Pull container image
Why does the workflow pull the image explicitly before Syft runs?

```text
The workflow pulls the image explicitly so the target image is available locally before Syft and Trivy analyze it. This also makes image download or tag problems fail early and clearly before the SBOM and scanning steps run.
```

#### Step: Generate CycloneDX SBOM with Syft
What does `anchore/sbom-action@v0` do? What is the output file used for?

```text
anchore/sbom-action@v0 runs Syft to inspect the container image and generate a SBOM. The CycloneDX JSON output file, juice-shop.cdx.json, is a machine-readable inventory of packages and components, and it is later used as input for Grype.
```

#### Step: Scan SBOM with Grype
What does `anchore/scan-action@v7` do with the SBOM? Why is `fail-build: false` set here?

```text
anchore/scan-action@v7 runs Grype against the generated SBOM and matches the listed components against known vulnerability data. fail-build: false is set so the lab workflow still completes and uploads reports even when vulnerabilities are found.
```

#### Step: Scan image with Trivy
How does this step differ from the Grype step? Why run both in the same pipeline?

```text
The Trivy step scans the container image directly, while the Grype step scans the SBOM file generated by Syft. Running both provides comparison between two common SCA tools and helps show how SBOM-based scanning and direct image scanning can produce complementary results.
```

#### Step: Upload security reports
What artifact is uploaded, and why use `if: always()`?

```text
The workflow uploads the contents of labs/lab4/reports/ as the artifact named lab4-sbom-sca-reports. if: always() ensures the reports are uploaded even if an earlier scan step fails, making the generated evidence available for review and troubleshooting.
```

### One-paragraph reflection (2-3 sentences)
How does this CI pipeline complement the local Syft + Grype workflow from Lab 4.1?

```text
This CI pipeline complements the local Syft + Grype workflow from Lab 4.1 by moving the same SBOM and vulnerability analysis into an automated GitHub Actions process. Instead of relying only on manual local commands, the scans can run consistently on PRs and pushes, producing downloadable reports for review in the CI system.
```