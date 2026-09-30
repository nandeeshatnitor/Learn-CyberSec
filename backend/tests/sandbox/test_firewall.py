from collections.abc import Sequence

import pytest

from app.sandbox.firewall import CHAIN, CommandResult, HostFirewall
from app.sandbox.runtime import SandboxError


class Recorder:
    """A fake iptables: `-C` succeeds only for rules that were already added."""

    def __init__(self) -> None:
        self.rules: set[tuple[str, ...]] = set()
        self.chains: set[str] = set()
        self.commands: list[tuple[str, ...]] = []
        self.fail_with: str | None = None

    def run(
        self, argv: Sequence[str], *, timeout: float, stdin: bytes | None = None
    ) -> CommandResult:
        args = tuple(argv[3:])  # drop: iptables -w 5
        self.commands.append(args)
        if self.fail_with:
            return CommandResult(1, "", self.fail_with)
        op, chain, *rest = args
        if op == "-N":
            if chain in self.chains:
                return CommandResult(1, "", "iptables: Chain already exists.")
            self.chains.add(chain)
        elif op == "-C":
            return CommandResult(0 if (chain, *rest) in self.rules else 1, "", "")
        elif op == "-A":
            self.rules.add((chain, *rest))
        elif op == "-I":
            self.rules.add((chain, *rest[1:]))
        return CommandResult(0, "", "")


def test_installs_a_default_drop_chain_for_lab_bridges() -> None:
    runner = Recorder()
    HostFirewall(runner).ensure()
    assert CHAIN in runner.chains
    assert (CHAIN, "-j", "DROP") in runner.rules
    assert (
        CHAIN,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ) in runner.rules
    assert ("INPUT", "-i", "cvl+", "-j", CHAIN) in runner.rules


def test_it_is_idempotent() -> None:
    runner = Recorder()
    first = HostFirewall(runner)
    first.ensure()
    added = len(runner.rules)
    HostFirewall(runner).ensure()  # a second process
    assert len(runner.rules) == added
    appended = [c for c in runner.commands if c[0] in ("-A", "-I")]
    assert len(appended) == added


def test_replies_are_accepted_before_the_drop() -> None:
    runner = Recorder()
    HostFirewall(runner).ensure()
    order = [c for c in runner.commands if c[0] == "-A"]
    assert "ACCEPT" in order[0] and order[1][-1] == "DROP"


def test_a_failing_firewall_is_reported_so_the_lab_does_not_start() -> None:
    runner = Recorder()
    runner.fail_with = "iptables: Permission denied (you must be root)."
    with pytest.raises(SandboxError) as info:
        HostFirewall(runner).ensure()
    assert info.value.code == "host_firewall_unavailable"


def test_a_missing_binary_is_reported() -> None:
    class Missing:
        def run(
            self, argv: Sequence[str], *, timeout: float, stdin: bytes | None = None
        ) -> CommandResult:
            raise FileNotFoundError("iptables")

    with pytest.raises(SandboxError) as info:
        HostFirewall(Missing()).ensure()
    assert info.value.code == "host_firewall_unavailable"
