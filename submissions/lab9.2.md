# Lab 9.2 — Submission

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

# Rule 1:
# runAsNonRoot must be set to true.
#
# It can be configured at:
# - Pod level: spec.template.spec.securityContext.runAsNonRoot
# - Container level: container.securityContext.runAsNonRoot
#
# A container is denied only when runAsNonRoot is not true
# at both the Pod level and the container level.
deny contains msg if {
    container := input.spec.template.spec.containers[_]

    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not container.securityContext.runAsNonRoot == true

    msg := sprintf(
        "Container %q must set runAsNonRoot=true at pod or container level",
        [container.name],
    )
}

# Rule 2:
# Every container must disable privilege escalation.
deny contains msg if {
    container := input.spec.template.spec.containers[_]

    not container.securityContext.allowPrivilegeEscalation == false

    msg := sprintf(
        "Container %q must set securityContext.allowPrivilegeEscalation=false",
        [container.name],
    )
}

# Rule 3:
# Every container must drop all Linux capabilities.
deny contains msg if {
    container := input.spec.template.spec.containers[_]

    not "ALL" in container.securityContext.capabilities.drop

    msg := sprintf(
        "Container %q must include ALL in securityContext.capabilities.drop",
        [container.name],
    )
}

# Rule 4 - Optional:
# Every container must define a memory limit.
deny contains msg if {
    container := input.spec.template.spec.containers[_]

    not container.resources.limits.memory

    msg := sprintf(
        "Container %q must set resources.limits.memory",
        [container.name],
    )
}

# Rule 5 - Optional:
# Every container image must be pinned using a SHA-256 digest.
#
# Valid:
# nginx@sha256:abc123...
#
# Invalid:
# nginx:latest
# nginx:1.27
deny contains msg if {
    container := input.spec.template.spec.containers[_]

    not contains(container.image, "@sha256:")

    msg := sprintf(
        "Container %q image %q must use an immutable sha256 digest",
        [container.name, container.image],
    )
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
<paste conftest output — must show ≥2 distinct deny messages,
 e.g. runAsNonRoot + allowPrivilegeEscalation + dropped capabilities>
 FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" image "bkimminich/juice-shop:latest" must use an immutable sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must set runAsNonRoot=true at pod or container level
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must set securityContext.allowPrivilegeEscalation=false

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
<paste both runs — PASS on juice-compose.yml, FAIL on /tmp/bad-compose.yml —
 showing the same deny[msg] pattern works on input.services>
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```