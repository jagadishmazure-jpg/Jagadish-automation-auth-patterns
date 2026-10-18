"""Tests: hash-chained audit log."""
from authpatterns.audit import AuditLog, fingerprint
from authpatterns.clock import FakeClock


def make_log():
    return AuditLog(FakeClock())


def test_chain_verifies_on_clean_log():
    log = make_log()
    log.record("auth.ok", "agent-1")
    log.record("auth.ok", "agent-2")
    assert log.verify()


def test_empty_log_verifies():
    assert make_log().verify()


def test_entries_are_sequenced_and_linked():
    log = make_log()
    log.record("a", "p1")
    log.record("b", "p2")
    entries = log.entries()
    assert [e["seq"] for e in entries] == [0, 1]
    assert entries[1]["prev"] == entries[0]["hash"]
    assert entries[0]["prev"] == "GENESIS"


def test_tampering_with_detail_breaks_chain():
    log = make_log()
    log.record("auth.ok", "agent-1")
    log.record("auth.ok", "agent-2")
    log._entries[0]["detail"] = "forged"
    assert not log.verify()


def test_tampering_with_principal_breaks_chain():
    log = make_log()
    log.record("auth.ok", "agent-1")
    log._entries[0]["principal"] = "attacker"
    assert not log.verify()


def test_reordering_breaks_chain():
    log = make_log()
    log.record("first", "p")
    log.record("second", "p")
    log._entries.reverse()
    assert not log.verify()


def test_fingerprint_is_stable_but_not_reversible():
    fp1 = fingerprint("s3cr3t")
    fp2 = fingerprint("s3cr3t")
    assert fp1 == fp2
    assert "s3cr3t" not in fp1
    assert fingerprint("other") != fp1
