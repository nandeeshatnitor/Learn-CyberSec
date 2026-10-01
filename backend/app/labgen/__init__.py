"""Candidate-lab pipeline (phase 5): from documented CVE research to a *candidate* lab that a human
must approve before any student can reach it.

    CVE → research guide → affected versions → objectives → candidate specification
        → build → automated validation → security validation → HUMAN APPROVAL → publish (lab-vN)

Design rules, enforced in code and tests:

* **Nothing generated reaches students without a human.** The pipeline job can never publish; only
  `LabPublisher.approve`, called from an authenticated reviewer's request, creates a `LabVersion`.
* **Generated code is never copied from the web or written freely by a model.** Labs come from
  vetted *blueprints* (small, intentionally vulnerable, deterministic apps written and reviewed in
  this repository) whose parameters are values extracted from the guide and then strictly
  re-validated. A language model may only polish wording, and even that is checked.
* **Every candidate is treated as hostile until proven otherwise**: statically scanned, built with no
  network, started in the sandbox, and exercised (exploit, fix, isolation, limits, cleanup, reset).
* **Published labs are immutable.** A change is a new version (`<family>-v2`); learners' records keep
  pointing at the version they used.
"""
