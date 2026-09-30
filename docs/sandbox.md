# Sandboxed labs (phase 4)

Students reproduce a weakness hands-on inside a **disposable, isolated environment**: a locked-down
container running an *intentionally vulnerable toy application*, a browser terminal into it, and a
verifier that checks what the lab *does*. This phase deliberately does **not** give access to anything
else. There is no code path that runs an arbitrary image, mounts a host path, publishes a port, or
connects to an address that is not a lab's own private address.

* Only labs defined in this repository (`labs/*/lab.json`) can be started. A definition is validated
  like untrusted input and cannot express a mount, a capability, a privileged flag, a published port or an
  image outside the allow-list.
* Only labs the platform's own team wrote and built: **not arbitrary CVEs.** The demo lab is a toy
  document portal with a path-traversal flaw (CWE-22), offered next to any learning session whose CVE has
  that weakness.
* The whole feature is off unless `SANDBOX_ENABLED=true`, and needs a container runtime the platform may
  drive (see [Deployment](#deployment)).

Code: `backend/app/sandbox/`, `app/api/routes/sandbox.py`, `app/workers/sandbox_worker.py`,
`frontend/src/components/lab/`, pages `/labs` and `/lab/[instanceId]`, lab definitions in `labs/`.

## Architecture

```
Student ──► /lab/…  (Next.js)  ──same-origin route handlers──►  API  ──►  Sandbox Manager
   │                                                                            │
   │ WebSocket (single-use ticket)                       ┌──────────────────────┼─────────────────────┐
   └──────────────► Terminal Gateway ─────┐              ▼                      ▼                     ▼
                                          │       Lab Template          Instance Manager      Network Controller
                     docker exec + pty    │       (validated JSON)      (lifecycle, reset)    (private net, proof)
                                          ▼                                   │                     │
                                    ┌───────────┐                             └──► Cleanup Manager ─┘
                                    │  the lab  │ ◄── Verifier / App proxy (the only things that connect *into* it)
                                    └───────────┘
```

| Component | Code | Responsibility |
| --- | --- | --- |
| **Lab Template** | `template.py`, `labs/*/lab.json` | What a lab is: image, ports, start command, limits, verification, timeout. Strict schema, platform ceilings (`PlatformLimits`), image allow-list. A broken definition is reported and skipped, never started. |
| **Instance Manager** | `instances.py` | `start` / `reset` / `stop` / lease enforcement; the state machine; one live lab per learner; capacity and rate limits. |
| **Network Controller** | `network.py`, `firewall.py` | One `--internal` bridge network with its own /28 per lab; the host firewall rule; the **isolation proof** that gates every start. |
| **Cleanup Manager** | `cleanup.py`, `workers/sandbox_worker.py` | Expiry, teardown, dead labs, stuck starts, orphaned resources found by label. Safe to run in several copies. |
| **Sandbox Manager** | `manager.py` | The facade the API talks to: ownership, rate limits, views (never the secret, image, container name or address), progress in learning sessions. |
| Runtime | `runtime.py`, `docker_runtime.py` | The `ContainerRuntime` boundary and its Docker CLI implementation (no shell, no SDK). A fixed `docker run` command line; `audit_container` re-checks the *running* container. |
| **Verifier** | `verifier.py` | Objectives checked against behaviour (below). |
| **Terminal Gateway** | `terminal.py` | Browser WebSocket ⇄ `docker exec` on a local pty. |
| App proxy | `proxy.py`, `app_client.py` | The lab's web app served through the platform. |

Student flow: **Start lab → Sandbox Manager creates network → proves isolation → starts the container →
audits it → waits for readiness → returns a temporary lab page → the student works (terminal, app,
objectives) → Verifier → the lab is destroyed** (student stops it, resets it, or its lease ends).

## The lab definition

`labs/<id>/lab.json` (+ a `Dockerfile` and the app). The fields that matter:

| Field | Meaning / rule |
| --- | --- |
| `id` | `^[a-z0-9][a-z0-9-]{2,62}$` and equal to the directory name. |
| `cve_id`, `cwe_ids` | A lab teaches a specific CVE (`cve_id`) or a weakness class (`cwe_ids`). It is offered beside a learning session when either matches the session's CVE. The demo lab is `cve_id: null`, `cwe_ids: ["CWE-22"]`. |
| `image` | `repository/name:tag`, from an allow-listed repository (`SANDBOX_ALLOWED_IMAGE_PREFIXES`, default `cvelearn-lab/`), never a digest reference, **never pulled**: it must already exist locally (`make lab-images`). |
| `ports` | Only these are ever contacted by the platform (`name`, `container_port` ≥ 1024, `http`/`tcp`). Nothing is published on the host. |
| `startup_command` | argv list. The platform wraps it: `timeout -s KILL <lease+grace> …` (see [Timeout](#timeout-and-cleanup)). |
| `shell` | argv for the terminal (default `/bin/sh`). |
| `user` | Non-zero `uid:gid`. **Root is not expressible.** |
| `resources` | `cpus`, `memory_mb`, `pids`, `tmpfs_mb`, each range-checked and capped by the platform (`SANDBOX_MAX_*`). |
| `writable_paths` | The only writable places: small tmpfs mounts (`noexec,nosuid,nodev`, size-limited). Sensitive paths (`/`, `/etc`, `/proc`…) are refused. |
| `network` | `{"egress": "none"}` is the only supported policy. |
| `timeout_minutes` | The lease, 1 – `SANDBOX_MAX_TIMEOUT_MINUTES`. |
| `verification` | `ready` check, optional `restart_command`, and `checks` (below). |

Unknown fields are refused (`extra="forbid"`), so a definition that tries `privileged`, `volumes` or
`cap_add` fails to load (tested).

## Lifecycle

```
STARTING ──► RUNNING ──► EXPIRED ──► STOPPING ──► STOPPED
   │            │  └──────────────────►┘ ▲
   │            └──────────────────────► FAILED
   └──► FAILED / STOPPING
```

| State | Meaning |
| --- | --- |
| `STARTING` | Row committed, resources being created. |
| `RUNNING` | Isolated, audited, ready. Terminal, app and verification are available. |
| `EXPIRED` | The lease ran out; the resources still exist and are being removed. |
| `STOPPING` | Teardown in progress (student stop, reset, or after expiry). If it fails it stays here and is retried. |
| `STOPPED` | Terminal: container and network confirmed gone (`cleaned_at`). |
| `FAILED` | Terminal: it never became usable, or died; resources removed. `failure_code` is one of a fixed set. |

Every move is a **conditional `UPDATE … WHERE status IN (…)`** (`SandboxRepository.transition`) checked
against the allowed-transition table, so a student's click, the cleanup worker and a second API process
can race without tearing a lab down twice or bringing one back. A **partial unique index** (one live lab per
learner) makes "two simultaneous Start clicks" race-free in the database itself.

**Reset** = destroy the current instance and everything in it (container, tmpfs state, network, tickets,
the app URL), then create a *new* instance (new id, new secret, new network, new URL) from the template and
return it. The old row becomes `STOPPED` with `stop_reason=reset`; verified objectives are kept (they are
progress, not lab state). If the replacement cannot start, the old lab is still gone.

## Container requirements

Fixed by `build_run_argv` (not configurable per lab) and re-checked on the running container by
`audit_container`, which destroys a lab that deviates. "Evidence" is what
`tests/sandbox/test_docker_integration.py` checks on **real Docker**, not just on the command line.

| Requirement | How | Evidence (real containers) |
| --- | --- | --- |
| CPU limit | `--cpus` (0.5 in the demo) | `NanoCpus` audited; |
| Memory limit, no swap | `--memory` = `--memory-swap` | a process allocating 400 MB in a 128 MB lab is killed |
| Process limit | `--pids-limit` (64) | a fork bomb is refused at the limit (`pids.events max > 0`, "Resource temporarily unavailable"), and the lab recovers |
| Filesystem isolation | `--read-only` root; only size-limited `tmpfs` for scratch (`noexec,nosuid,nodev`); no bind mounts, no volumes | writes to `/etc`, `/opt` fail; a script written to `/lab` cannot be executed; a 64 MB write to a 16 MB scratch area fails; `Mounts` and `Binds` contain no host path |
| No host mount, no Docker socket | never passed; audit rejects any non-tmpfs mount or `docker.sock` | the socket does not exist inside the lab |
| No privileged / no capabilities | `--cap-drop ALL`, `no-new-privileges`, default seccomp + AppArmor kept | `CapEff` is all zeros, `NoNewPrivs 1`, `su root` fails |
| Not root | `--user 10001:10001` (root not expressible in a definition) | `id -u` = 10001 in the app and in the terminal |
| Network isolation | private `--internal` network per lab, host firewall rule, isolation proof | see below |
| Execution timeout / expiry | the lease; `timeout -s KILL` around the start command | a lab with a 5 s lease is killed by itself (exit 137) with **no** worker running |
| Cleanup | cleanup worker + on-access enforcement + label sweep | expired, killed, orphaned and reset labs leave no container or network |

The container also gets `--init` (the kill switch depends on it, and the audit requires it), `--ipc private`,
`--restart no`, a small `/dev/shm`, `nofile`/`core` ulimits, capped json logs, and labels
`cvelearn.managed/instance/kind/expires` for cleanup.

## Network isolation

Default policy: **deny everything.** A lab can be reached by the platform on its declared ports and
can reach nothing.

* Each lab gets its **own** `--internal` bridge (`cvl-…`, a private /28 from `SANDBOX_SUBNET_POOL`,
  default `10.200.0.0/16`): no route to the internet, to the cloud metadata address, or to other labs
  (different networks). DNS answers `SERVFAIL` for external names.
* **A finding worth knowing** (measured on real Docker, and kept as a test): an `--internal` network does
  *not* stop a container reaching services on the **host itself** through the bridge's gateway address. A
  process listening on `0.0.0.0` (the platform's database, Redis, a Docker API on TCP…) was reachable from the
  lab. `HostFirewall` therefore installs, once, a chain `CVELEARN-LABS` that accepts only replies to
  connections the host opened (the platform's own health checks and app proxy) and **drops everything else
  arriving from any `cvl+` interface**.
  (`gateway_mode_ipv4=isolated` would also block the host, but then the platform could not reach the lab at all.)
* **The isolation proof** does not trust configuration. Before the student's container exists, a throw-away
  probe container on the *same network* tries to connect to: a listener the platform opens on all its
  interfaces (the strongest test of the firewall), common host service ports plus the platform's own database and
  Redis ports, `1.1.1.1`, `8.8.8.8`, the metadata endpoints (`169.254.169.254`, `169.254.170.2`, and by name),
  name resolution, and every other live lab. **Any success, or a probe that cannot run, aborts the start
  (`isolation_check_failed`)** and nothing is left behind. Tested on real Docker both ways: with the
  firewall rule removed the lab is *refused*; with it, every target is blocked. The same proof can be re-run
  on demand from the lab page (Isolation tab).
* Only the platform connects *in*: the verifier and the app proxy, to the lab's recorded address inside the pool
  and a declared port, as plain GET/HEAD/POST to a validated path, with no redirects and no environment proxies.

"Allow only explicitly required communication" is the `ports` list: those are the only endpoints ever contacted.
Definitions cannot open a path *out*; supporting egress allow-lists would be a reviewed change to this design
(multi-container labs with per-lab firewall rules).

## Reaching the lab

* **Terminal.** `Browser → WebSocket → Terminal Gateway → docker exec on a pty → the lab.` The browser first
  asks its own site for a **single-use ticket** (random, stored only as a hash, ~30 s, bound to one lab and one
  learner, revoked when the lab ends); the WebSocket cannot carry the learner cookie to another origin, hence the
  ticket. The gateway checks the `Origin`, consumes the ticket atomically, runs the *definition's* shell as the lab's
  unprivileged user, and pumps bytes. The browser controls only what it types and the window size (both clamped);
  it never sees a container name, an address or the runtime. The session ends when the lab stops, expires or is reset,
  after `SANDBOX_TERMINAL_IDLE_SECONDS`, or when either side leaves; at most a few terminals per lab. Rejections are
  accepted-then-closed with a code so the page can say *why*.
* **The lab's web app.** Served at `/lab-app/<instance>/<token>/…` through the platform (never a published port). A
  sandboxed frame cannot send cookies, so the URL itself carries a random per-lab token (a capability, cleared when the
  lab ends). The lab's output is untrusted: every response carries `Content-Security-Policy: sandbox allow-scripts
  allow-forms` (no `allow-same-origin`: scripts get an opaque origin and reach neither the platform's cookies nor its
  APIs), `nosniff`, `no-store`, no cookies are relayed, only a fixed set of headers passes, redirects stay inside the
  prefix, and absolute links in HTML are rewritten under it. The page embeds it with `sandbox="allow-forms allow-scripts"`.
  Paths reach the lab exactly as sent (dot-dot segments included: that is the exercise).

## Verification

The verifier decides whether an objective was **achieved**, from what the running lab does, never from which
command the student ran.

| Check kind | What it does |
| --- | --- |
| `payload_replay` | The student submits a request path. The verifier sends it to *their* lab and passes only if the answer contains this instance's random secret. Typing `cat /lab/private/canary.txt` is not a request the app answers, so it fails; the secret cannot be pasted into the request; the secret of another lab does not count. |
| `regression` | After a fix: restart the app (`restart_command`), replay the template's attack variants *and the student's own working payload* (the secret must not come back), and exercise legitimate behaviour (it must still work: "break everything" and an over-strict fix that rejects sub-folders both fail). |

`requires` orders objectives (the fix cannot be verified before the exploit). Results are stored per instance
(`lab_verifications`: attempts, first pass time, the evidence payload); a pass is never taken back by a later miss, and
progress survives a reset.

Limits, stated plainly: a student with a shell in the lab can read the secret file directly, or edit the app to print it.
That is why the exploit objective asks for a *working request*, and the fix objective for *behaviour*, but a determined
student can still cheat themselves. Labs are not proctored.

## Timeout and cleanup

Three independent layers, so no lab outlives its lease:

1. **On access:** the API expires a lab past its lease the moment anyone touches it (and refuses it), then tears it down.
2. **The cleanup worker** (`python -m app.workers.sandbox_worker`, every `SANDBOX_CLEANUP_INTERVAL_SECONDS`): expires
   leases; fails stuck `STARTING` rows; marks `RUNNING` labs whose container died `FAILED`; finishes teardowns a crashed
   worker left half done; and removes **orphans found by label** (a crash between creating and recording, a restored database):
   the runtime is listed *first* and the database read second, so a lab being started is never mistaken for an orphan.
3. **The container's own kill switch:** the start command is wrapped in `timeout -s KILL lease+grace`, so even if the
   platform is down entirely the container ends itself.

## Progress integration

`GET /api/sandbox/sessions/{session_id}/labs` returns the labs that fit the session's CVE (by `cve_id`, then by shared
CWE) with the learner's verified objectives; the lesson page shows them in the left column ("Hands-on lab", *0 of 2 objectives
verified*, Start / Resume), the lab page links back to the lesson, and the completed-session summary lists lab progress.
Progress is derived from `lab_verifications` across the learner's instances for that session, so it survives resets and
expired labs. Labs do not change the learning score: it stays a secondary signal.

## API

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/sandbox/labs[?cve_id=]`, `/labs/{lab_id}` | Catalogue (no image, command or runtime details). |
| POST | `/api/sandbox/instances` | `{lab_id, session_id?}`. 409 already have one, 429, 503 capacity/disabled, 502 `lab_start_failed` (fixed message). |
| GET | `/api/sandbox/instances/current`, `/instances/{id}` | State, lease (`seconds_remaining`), objectives, `app_path`. |
| POST | `/api/sandbox/instances/{id}/reset`, `/stop` | |
| POST | `/api/sandbox/instances/{id}/verify` | `{check_id, payload?}` → outcome `passed/failed/blocked/error` + the instance. |
| POST | `/api/sandbox/instances/{id}/network-check` | Re-run the isolation proof now. |
| POST | `/api/sandbox/instances/{id}/terminal-ticket` | Single-use ticket for the WebSocket. |
| GET | `/api/sandbox/sessions/{session_id}/labs` | Labs + verified objectives for a learning session. |
| GET/HEAD/POST | `/api/sandbox/app/{id}/{token}/…` | The lab's web app (capability URL; used through `/lab-app/…`). |
| WS | `/api/sandbox/terminal/ws?ticket=` | The Terminal Gateway. |

Learner endpoints use the anonymous learner token like the learning API; another learner's lab is a 404.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `SANDBOX_ENABLED` | `false` | Master switch. |
| `SANDBOX_LAB_DIR` | `<repo>/labs` | Where definitions live. |
| `SANDBOX_DOCKER_BINARY`, `SANDBOX_DOCKER_HOST` | `docker`, unset | Use a *dedicated* daemon (see below). |
| `SANDBOX_ALLOWED_IMAGE_PREFIXES` | `cvelearn-lab/` | Images must come from here and exist locally. |
| `SANDBOX_PROBE_IMAGE` | `cvelearn-lab/net-probe:1` | The isolation probe. |
| `SANDBOX_SUBNET_POOL` | `10.200.0.0/16` | A /28 per lab. |
| `SANDBOX_MANAGE_HOST_FIREWALL`, `SANDBOX_ISOLATION_GATE` | `true`, `true` | Leave the gate on. |
| `SANDBOX_TIMEOUT_SCALE` | `1.0` | Only ever *shortens* leases (demos, tests). |
| `SANDBOX_CONTAINER_GRACE_SECONDS` | `60` | Kill switch slack after the lease. |
| `SANDBOX_MAX_ACTIVE_INSTANCES`, `SANDBOX_STARTS_PER_LEARNER_PER_HOUR` | `20`, `12` | Capacity and abuse limits. |
| `SANDBOX_MAX_CPUS/MEMORY_MB/PIDS/TMPFS_MB/TIMEOUT_MINUTES` | 2 / 1024 / 512 / 64 / 240 | Ceilings a definition may not exceed. |
| `SANDBOX_TERMINAL_PUBLIC_URL` | unset | Base `ws(s)://` URL of the gateway if it is not on the site's own origin. |
| `SANDBOX_TERMINAL_IDLE_SECONDS`, `…_MAX_PER_INSTANCE`, `…_TICKET_TTL_SECONDS` | 600, 2, 30 | |
| `TERMINAL_WS_ORIGIN` *(frontend, runtime)* | unset | The same origin, allowed in the page's `connect-src`. |

## Deployment

The sandbox needs three things the rest of the platform does not:

1. **A Docker daemon the backend may drive, and the `docker` CLI.** Whoever can talk to that daemon is effectively root on
   its host. Run the sandbox against a **dedicated host/VM or a rootless daemon** (`SANDBOX_DOCKER_HOST`), never the daemon
   that runs the platform's own database, and **never mount the daemon's socket into an internet-facing container**. For
   this reason `docker-compose.yml` does not enable the sandbox: run the API and `sandbox_worker` where the runtime is.
2. **Root (or `CAP_NET_ADMIN`) for the host firewall rule** — or install an equivalent rule yourself and set
   `SANDBOX_MANAGE_HOST_FIREWALL=false`. The isolation gate refuses labs if it is missing either way.
3. **The images, built locally:** `make lab-images` (they are never pulled).

Then `SANDBOX_ENABLED=true`, run the API and `make sandbox-worker`, and set `SANDBOX_TERMINAL_PUBLIC_URL` /
`TERMINAL_WS_ORIGIN` if the gateway is on another origin. Behind a reverse proxy, route `/api/sandbox/terminal/` with
WebSocket upgrade support.

For stronger isolation than a shared kernel, run the Docker daemon with a sandboxed runtime (gVisor `runsc`, Kata) —
the definition needs no change.

## Adding a lab

1. `labs/<id>/` with a `Dockerfile` (`USER 10001:10001`, a `start.sh` that plants `$LAB_CANARY` where only the weakness
   exposes it, and a `restart.sh`), the app, and a `lab.json`.
2. An image tagged `cvelearn-lab/<id>:<n>`; the image needs `timeout` (busybox is enough) and, for the terminal, a shell.
3. Objectives that check *behaviour* (see Verification). The definition loads only if it validates and fits the ceilings.
4. Tests: the template tests load every definition; add a fake-app test for the verifier and, if the lab has new
   behaviour, a real-Docker test.

## Tests

* `backend/tests/sandbox/` (~300 tests, no Docker needed): template validation, the exact `docker run`/`network create`
  arguments (a forbidden flag anywhere fails), the container audit, the firewall, the network controller and isolation
  proof (incl. fail-closed), the whole lifecycle with an in-memory runtime, cleanup and orphans, the verifier against an
  emulated vulnerable app, the API (ownership, disabled, error mapping), the app proxy and the WebSocket terminal.
* `tests/sandbox/test_docker_integration.py` (21 tests, **real Docker**, opt-in: `make test-sandbox-docker`): the
  container audit, sealed filesystem, unprivileged user, Docker socket absence, no route to the internet/metadata/host/other
  labs, a missing firewall rule refusing the lab, fork bomb, memory, tmpfs size, a real pty terminal, the real vulnerability
  exploited and the real fix verified, breaking the app rejected, reset destroying state, the in-container kill switch
  with no worker, expiry cleanup, orphan removal by label, a killed container detected.
* Frontend: proxies (allow-list, raw path, header filtering), the terminal (mocked xterm/WebSocket), the lab workspace,
  the lesson integration, the security headers.

## Known limitations

* **Containers share the host kernel.** A kernel or runtime vulnerability would break out of any container; use a sandboxed
  runtime for anything beyond teaching labs of your own making, and keep the host patched.
* The platform component that drives Docker is highly privileged (see Deployment); the design keeps its inputs
  fixed (repository definitions, a fixed command line, no user-controlled argv), but it is a high-value target.
* The isolation proof and firewall rule cover IPv4 on Docker's bridge networks; IPv6 is disabled on lab networks and not
  otherwise addressed. The measured behaviour above is for Docker 29 with cgroup v1; re-run
  `make test-sandbox-docker` on any new host or Docker version.
* No disk quota beyond the size-limited tmpfs (the root filesystem is read-only); no bandwidth limit (there is no network).
* One container per lab; no egress allow-lists; no per-lab GPU/devices.
* The per-lab terminal counter is per API process; with several API replicas the cap is approximate.
* Verification of the "fix" objective restarts the student's app: a lab image must tolerate that (the demo supervises it).
