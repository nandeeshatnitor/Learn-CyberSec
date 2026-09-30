"""The exact `docker run` / `docker network create` command lines, and the audit of a running
container. These are the isolation guarantees, so they are asserted flag by flag."""

import copy
from typing import Any

import pytest

from app.sandbox.docker_runtime import build_network_argv, build_run_argv
from app.sandbox.runtime import ContainerSpec, NetworkSpec, TmpfsMount, audit_container

SPEC = ContainerSpec(
    name="cvl-lab-abc",
    image="cvelearn-lab/path-traversal-101:1",
    network="cvl-net-abc",
    command=("timeout", "-s", "KILL", "100", "/opt/lab/start.sh"),
    user="10001:10001",
    cpus=0.5,
    memory_mb=128,
    pids=64,
    tmpfs=(
        TmpfsMount("/tmp", 16, "1777", 10001, 10001),
        TmpfsMount("/lab", 16, "0755", 10001, 10001),
    ),
    env={"LAB_CANARY": "CVL-secret", "LAB_LEASE_SECONDS": "60"},
    labels={"cvelearn.managed": "true", "cvelearn.instance": "abc"},
)

FORBIDDEN = [
    "--privileged",
    "--cap-add",
    "--device",
    "--volume",
    "-v",
    "--mount",
    "--publish",
    "-p",
    "-P",
    "--publish-all",
    "--pid",
    "--userns",
    "--uts",
    "--volumes-from",
    "--link",
    "--add-host",
    "--security-opt=seccomp=unconfined",
    "seccomp=unconfined",
    "apparmor=unconfined",
    "--cgroup-parent",
    "--group-add",
]


def argv(**overrides: Any) -> list[str]:
    spec = ContainerSpec(**{**SPEC.__dict__, **overrides})
    return build_run_argv("docker", spec, detach=True, remove=False)


def pairs(items: list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for index, item in enumerate(items[:-1]):
        if item.startswith("--"):
            found.setdefault(item, []).append(items[index + 1])
    return found


@pytest.mark.parametrize("flag", FORBIDDEN)
def test_no_forbidden_flag_is_ever_in_the_command(flag: str) -> None:
    assert flag not in argv()
    assert flag not in argv(env={}, tmpfs=())


def test_the_docker_socket_and_host_paths_never_appear() -> None:
    joined = " ".join(argv())
    assert "docker.sock" not in joined
    assert "/var/run" not in joined
    assert "type=bind" not in joined
    assert " /:" not in joined


def test_the_fixed_isolation_posture_is_present() -> None:
    options = pairs(argv())
    assert options["--cap-drop"] == ["ALL"]
    assert options["--security-opt"] == ["no-new-privileges:true"]
    assert "--read-only" in argv()
    assert options["--pull"] == ["never"]
    assert options["--network"] == ["cvl-net-abc"]
    assert options["--user"] == ["10001:10001"]
    assert options["--ipc"] == ["private"]
    assert options["--restart"] == ["no"]
    assert "--init" in argv()


def test_resource_limits_are_present_and_swap_is_disabled() -> None:
    options = pairs(argv())
    assert options["--cpus"] == ["0.5"]
    assert options["--memory"] == ["128m"]
    assert options["--memory-swap"] == ["128m"]  # equal to memory: no swap
    assert options["--pids-limit"] == ["64"]
    assert "nofile=512:512" in options["--ulimit"]
    assert options["--log-opt"] == ["max-size=256k", "max-file=1"]


def test_scratch_areas_are_small_memory_only_and_not_executable() -> None:
    tmpfs = pairs(argv())["--tmpfs"]
    assert tmpfs == [
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777,uid=10001,gid=10001",
        "/lab:rw,noexec,nosuid,nodev,size=16m,mode=0755,uid=10001,gid=10001",
    ]


def test_the_image_and_command_come_last_and_values_are_single_arguments() -> None:
    items = argv(env={"LAB_CANARY": "x; rm -rf / && $(evil)"})
    assert items[-6:] == ["cvelearn-lab/path-traversal-101:1", *SPEC.command]
    assert "LAB_CANARY=x; rm -rf / && $(evil)" in items  # passed verbatim, never through a shell


def test_detach_and_remove_are_only_added_when_asked() -> None:
    detached = build_run_argv("docker", SPEC, detach=True, remove=False)
    oneshot = build_run_argv("docker", SPEC, detach=False, remove=True)
    assert "--detach" in detached and "--rm" not in detached
    assert "--rm" in oneshot and "--detach" not in oneshot


def test_the_network_is_internal_with_its_own_subnet_and_bridge() -> None:
    spec = NetworkSpec(
        "cvl-net-abc", "cvl-abcd1234", "10.200.4.16/28", {"cvelearn.managed": "true"}
    )
    items = build_network_argv("docker", spec)
    options = pairs(items)
    assert "--internal" in items  # no route out: no internet, no metadata endpoint
    assert options["--subnet"] == ["10.200.4.16/28"]
    assert "com.docker.network.bridge.name=cvl-abcd1234" in options["--opt"]
    assert "--ipv6=false" in items
    assert items[-1] == "cvl-net-abc"
    assert "--attachable" not in items


# -- the audit of a running container --------------------------------------------------------
@pytest.fixture
def inspect_ok() -> dict[str, Any]:
    mem = SPEC.memory_mb * 1024 * 1024
    return {
        "HostConfig": {
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "ReadonlyRootfs": True,
            "Init": True,
            "PortBindings": {},
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "NetworkMode": SPEC.network,
            "PidsLimit": SPEC.pids,
            "Memory": mem,
            "MemorySwap": mem,
            "NanoCpus": 500_000_000,
            "RestartPolicy": {"Name": "no"},
        },
        "Config": {"User": SPEC.user},
        "Mounts": [{"Type": "tmpfs", "Destination": "/tmp"}],
        "NetworkSettings": {"Networks": {SPEC.network: {"IPAddress": "10.200.0.2"}}},
    }


def test_a_correctly_locked_down_container_passes_the_audit(inspect_ok: dict[str, Any]) -> None:
    assert audit_container(inspect_ok, SPEC) == []


def mutate(base: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    data = copy.deepcopy(base)
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (("HostConfig", "Privileged"), True, "privileged"),
        (("HostConfig", "CapAdd"), ["NET_ADMIN"], "capabilities were added"),
        (("HostConfig", "CapDrop"), [], "not all capabilities"),
        (("HostConfig", "CapDrop"), ["NET_RAW"], "not all capabilities"),
        (("HostConfig", "SecurityOpt"), [], "no-new-privileges"),
        (
            ("HostConfig", "SecurityOpt"),
            ["no-new-privileges:true", "seccomp=unconfined"],
            "security profile",
        ),
        (("HostConfig", "ReadonlyRootfs"), False, "writable"),
        (("HostConfig", "Binds"), ["/:/host"], "bind-mounted"),
        (("HostConfig", "PortBindings"), {"80/tcp": [{"HostPort": "80"}]}, "published"),
        (("HostConfig", "Devices"), [{"PathOnHost": "/dev/sda"}], "devices"),
        (("HostConfig", "PidMode"), "host", "PID namespace"),
        (("HostConfig", "IpcMode"), "host", "IPC"),
        (("HostConfig", "IpcMode"), "container:other", "IPC"),
        (("HostConfig", "UTSMode"), "host", "UTS"),
        (("HostConfig", "UsernsMode"), "host", "user namespaces"),
        (("HostConfig", "VolumesFrom"), ["db"], "volumes or links"),
        (("HostConfig", "NetworkMode"), "bridge", "own lab network"),
        (("HostConfig", "NetworkMode"), "host", "own lab network"),
        (("HostConfig", "PidsLimit"), 0, "process limit"),
        (("HostConfig", "PidsLimit"), None, "process limit"),
        (("HostConfig", "Memory"), 0, "memory limit"),
        (("HostConfig", "MemorySwap"), -1, "swap"),
        (("HostConfig", "MemorySwap"), 2**30, "swap"),
        (("HostConfig", "NanoCpus"), 0, "cpu limit"),
        (("HostConfig", "RestartPolicy"), {"Name": "always"}, "restart policy"),
        (("HostConfig", "Init"), False, "init process"),
        (("HostConfig", "Init"), None, "init process"),
        (("Config", "User"), "", "unprivileged"),
        (("Config", "User"), "0:0", "unprivileged"),
        (("Config", "User"), "root", "unprivileged"),
        (("Config", "User"), "10002:10002", "unprivileged"),
        (("Mounts",), [{"Type": "bind", "Source": "/", "Destination": "/host"}], "non-tmpfs"),
        (
            ("Mounts",),
            [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/d.sock"}],
            "docker socket",
        ),
        (("Mounts",), [{"Type": "volume", "Destination": "/data"}], "non-tmpfs"),
        (("NetworkSettings", "Networks"), {SPEC.network: {}, "bridge": {}}, "network other"),
    ],
)
def test_the_audit_catches_every_way_a_container_can_be_less_isolated(
    inspect_ok: dict[str, Any], path: tuple[str, ...], value: Any, expected: str
) -> None:
    problems = audit_container(mutate(inspect_ok, path, value), SPEC)
    assert any(expected in p for p in problems), problems
