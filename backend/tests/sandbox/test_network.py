"""Network Controller: subnet allocation, and the isolation proof that gates every lab start."""

import socket
import uuid

import pytest

from app.sandbox.network import HostListener, NetworkController
from app.sandbox.runtime import ExecResult, NetworkInfo, SandboxError
from tests.sandbox.fakes import FakeApps, FakeRuntime

IID = str(uuid.uuid4())


@pytest.fixture
def runtime() -> FakeRuntime:
    return FakeRuntime(FakeApps())


@pytest.fixture
def controller(runtime: FakeRuntime) -> NetworkController:
    return NetworkController(runtime, extra_host_ports=(5432, 6379), settle_seconds=0.3)


@pytest.fixture
def network() -> NetworkInfo:
    return NetworkInfo("cvl-net-x", "10.200.3.0/28", "10.200.3.1")


def test_a_network_gets_its_own_slash_28_labelled_for_cleanup(
    controller: NetworkController, runtime: FakeRuntime
) -> None:
    info = controller.create(IID, expires_at=1_000_000)
    spec = runtime.networks[info.name]
    assert spec.subnet.endswith("/28") and spec.subnet.startswith("10.200.")
    assert spec.bridge.startswith("cvl-") and len(spec.bridge) <= 15  # the firewall matches cvl+
    assert spec.labels["cvelearn.managed"] == "true"
    assert spec.labels["cvelearn.instance"] == IID
    assert spec.labels["cvelearn.expires"] == "1000000"
    assert controller.container_address(info).endswith(".2") or controller.container_address(info)


def test_the_host_firewall_is_ensured_before_any_network_exists(
    controller: NetworkController, runtime: FakeRuntime
) -> None:
    controller.create(IID, 1)
    order = [name for name, _ in runtime.calls]
    assert order.index("ensure_host_isolation") < order.index("create_network")


def test_a_failing_firewall_prevents_the_network(
    controller: NetworkController, runtime: FakeRuntime
) -> None:
    runtime.fail["ensure_host_isolation"] = SandboxError("host_firewall_unavailable")
    with pytest.raises(SandboxError):
        controller.create(IID, 1)
    assert not runtime.networks


def test_a_subnet_collision_is_retried_with_another_block(runtime: FakeRuntime) -> None:
    tries = {"n": 0}
    real = runtime.create_network

    def flaky(spec):  # type: ignore[no-untyped-def]
        tries["n"] += 1
        if tries["n"] < 3:
            raise SandboxError("subnet_in_use")
        return real(spec)

    runtime.create_network = flaky  # type: ignore[method-assign]
    NetworkController(runtime).create(IID, 1)
    assert tries["n"] == 3


def test_other_errors_are_not_retried(runtime: FakeRuntime) -> None:
    runtime.fail["create_network"] = SandboxError("runtime_unavailable")
    with pytest.raises(SandboxError) as info:
        NetworkController(runtime).create(IID, 1)
    assert info.value.code == "runtime_unavailable"


def test_the_pool_must_be_private_and_big_enough(runtime: FakeRuntime) -> None:
    with pytest.raises(ValueError):
        NetworkController(runtime, subnet_pool="8.8.0.0/16")
    with pytest.raises(ValueError):
        NetworkController(runtime, subnet_pool="10.0.0.0/28")


# -- the isolation proof ---------------------------------------------------------------------
def test_an_isolated_network_passes_and_covers_everything_that_must_be_unreachable(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo
) -> None:
    report = controller.prove_isolation(IID, network, peers=[("10.200.9.2", 8080)])
    assert report.passed
    names = [r.target for r in report.results]
    assert any("host running the platform" in n for n in names)
    assert any("Services on the host" in n for n in names)
    assert any("1.1.1.1" in n for n in names)
    assert any("169.254.169.254" in n for n in names)
    assert any("metadata.google.internal" in n for n in names)
    assert any("example.com" in n for n in names)
    assert any("Other students" in n for n in names)
    targets = " ".join(runtime.probes[0].command)
    assert (
        "10.200.3.1:5432" in targets and "10.200.3.1:6379" in targets
    )  # platform DB / Redis ports
    assert "10.200.9.2:8080" in targets


def test_the_probe_runs_as_a_locked_down_container_on_the_labs_own_network(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo
) -> None:
    controller.prove_isolation(IID, network)
    probe = runtime.probes[0]
    assert probe.network == network.name
    assert probe.user == "10001:10001"
    assert probe.labels["cvelearn.kind"] == "probe"
    assert probe.labels["cvelearn.instance"] == IID


@pytest.mark.parametrize(
    "leak", ["10.200.3.1:", "1.1.1.1", "169.254.169.254", "example.com", "10.200.9.2"]
)
def test_any_reachable_target_fails_the_proof(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo, leak: str
) -> None:
    runtime.reachable = {leak}
    report = controller.prove_isolation(IID, network, peers=[("10.200.9.2", 8080)])
    assert not report.passed
    assert any(r.reachable for r in report.results)


def test_a_probe_that_cannot_run_fails_closed(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo
) -> None:
    runtime.run_oneshot = lambda spec, timeout: ExecResult(1, "", "boom")  # type: ignore[method-assign]
    with pytest.raises(SandboxError) as info:
        controller.prove_isolation(IID, network)
    assert info.value.code == "isolation_check_failed"


def test_missing_answers_fail_closed(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo
) -> None:
    runtime.run_oneshot = lambda spec, timeout: ExecResult(0, "", "")  # type: ignore[method-assign]
    with pytest.raises(SandboxError):
        controller.prove_isolation(IID, network)


def test_the_host_listener_notices_a_real_connection() -> None:
    with HostListener() as listener:
        with socket.create_connection(("127.0.0.1", listener.port), timeout=2):
            pass
        for _ in range(50):
            if listener.hits:
                break
            socket.create_connection(("127.0.0.1", listener.port), timeout=2).close()
    assert listener.hits >= 1


def test_a_connection_to_the_host_listener_is_a_failure_even_if_the_probe_says_blocked(
    controller: NetworkController, runtime: FakeRuntime, network: NetworkInfo
) -> None:
    """Belt and braces: what the *host* saw wins over what the probe reported."""
    real = runtime.run_oneshot

    def sneaky(spec, timeout):  # type: ignore[no-untyped-def]
        target = next(t for t in spec.command if t.startswith(network.gateway))
        host, port = target.rsplit(":", 1)
        socket.create_connection(("127.0.0.1", int(port)), timeout=2).close()
        return real(spec, timeout)

    runtime.run_oneshot = sneaky  # type: ignore[method-assign]
    report = controller.prove_isolation(IID, network)
    assert not report.passed
