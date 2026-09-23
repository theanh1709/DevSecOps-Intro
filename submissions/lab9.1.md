# Lab 9.1 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{
    "hostname": "fc6a4463b0fe",
    "output": "2026-09-23T10:11:29.487303700+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=f6afe5fb1439 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "f6afe5fb1439",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
        "evt.time.iso8601": 1790158289487303700,
        "evt.type": "execve",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
        "proc.exepath": "/bin/busybox",
        "proc.name": "sh",
        "proc.pname": "runc",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": [
        "T1059",
        "container",
        "maturity_stable",
        "mitre_execution",
        "shell"
    ],
    "time": "2026-09-23T10:11:29.487303700Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
    "hostname": "fc6a4463b0fe",
    "output": "2026-09-23T10:11:29.582926326+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=f6afe5fb1439 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "f6afe5fb1439",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1790158289582926326,
        "evt.type": "open",
        "fd.name": "/etc/shadow",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.aname[2]": null,
        "proc.aname[3]": null,
        "proc.aname[4]": null,
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.pname": null,
        "proc.tty": 0,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": [
        "T1555",
        "container",
        "filesystem",
        "host",
        "maturity_stable",
        "mitre_credential_access"
    ],
    "time": "2026-09-23T10:11:29.582926326Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect file writes to /tmp inside a container
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp detected
    (container=%container.name
    user=%user.name
    file=%fd.name
    command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

# Detect possible cryptominer activity inside a container.
#
# Detection indicators:
# 1. A process connects to a commonly used mining-pool port.
# 2. The process name matches a known cryptocurrency miner.
#
# The indicators are joined with OR so either a suspicious mining port
# or a known miner process can trigger the alert.
- rule: Possible Cryptominer Activity
  desc: Detect a container process connecting to a common mining-pool port or running a known cryptominer process
  condition: >
    evt.type = connect
    and container.id != host
    and
    (
      fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
      or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible cryptominer activity detected
    (container=%container.name
    container_id=%container.id
    process=%proc.name
    command=%proc.cmdline
    target_ip=%fd.sip
    target_port=%fd.sport
    target_name=%fd.sip.name
    user=%user.name)
  priority: CRITICAL
  tags:
    - container
    - mitre_execution
    - mitre_command_and_control
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{
    "hostname": "fc6a4463b0fe",
    "output": "2026-09-23T10:20:59.122848286+0000: Warning Write to /tmp detected (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=f6afe5fb1439 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "f6afe5fb1439",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1790158859122848286,
        "fd.name": "/tmp/my-write.txt",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
        "user.name": "root"
    },
    "priority": "Warning",
    "rule": "Write to /tmp by container",
    "source": "syscall",
    "tags": [
        "container",
        "drift"
    ],
    "time": "2026-09-23T10:20:59.122848286Z"
}
```