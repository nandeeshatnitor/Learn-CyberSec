"""Sandboxed labs: disposable, isolated environments for hands-on practice (phase 4).

    SandboxManager            the facade the API talks to
      ├─ LabCatalog/LabTemplate   what can be started (validated, trusted repository content)
      ├─ InstanceManager          start / reset / stop, the lifecycle state machine
      ├─ NetworkController        one private no-egress network per lab, plus the isolation proof
      ├─ CleanupManager           expiry, teardown and orphan removal (run by a worker)
      ├─ Verifier                 checks the *behaviour* of the running lab
      └─ TerminalGateway          browser WebSocket -> gateway -> `docker exec` in the lab

This package only ever drives containers that come from the repository's own lab definitions. It
has no code path that runs an arbitrary image, mounts a host path, publishes a port, or reaches an
address that is not a lab's own private address.
"""
