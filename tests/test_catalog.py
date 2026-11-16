"""Catalog must cover every MHDDoS method, and every MHDDoS constant must survive extraction."""

from mhddos_trex import catalog


def test_every_upstream_method_is_registered(source):
    assert catalog.unimplemented(source) == []


def test_no_entry_references_a_removed_method(source):
    assert catalog.stale_deferred(source) == []


def test_registry_matches_upstream_sets(source):
    emitted = set(catalog.SPECS)
    assert emitted == set(source.methods)


def test_deferred_entries_are_never_emittable():
    for name, (verdict, reason) in catalog.DEFERRED.items():
        assert reason, f"{name} needs a reason"
        assert catalog.SPECS[name].verdict is verdict
        assert name not in catalog.emittable()


def test_extracted_amplifier_requests_are_intact(source):
    assert set(source.amplifiers) == {"MEM", "NTP", "DNS", "CHAR", "CLDAP", "ARD", "RDP"}
    payload, port = source.amplifiers["DNS"]
    assert payload[:2] == b"\x45\x67"
    assert port == 53
    assert source.amplifiers["MEM"][1] == 11211
    assert source.amplifiers["CHAR"][0] == b"\x01"


def test_extracted_protocol_payloads(source):
    assert source.protocol_payloads["VSE"] == b"\xff\xff\xff\xffTSource Engine Query\x00"
    assert source.protocol_payloads["TS3"][:4] == b"\x05\xca\x7f\x16"
    assert source.protocol_payloads["FIVEM"].startswith(b"\xff\xff\xff\xffgetinfo")
    assert len(source.protocol_payloads["MCPE"]) == 60


def test_extracted_http_fragments(source):
    assert source.browser_headers.startswith("Accept-Encoding: gzip")
    assert source.browser_headers.endswith("\r\n")
    assert len(source.ovh_udp_methods) == 5
    assert source.ovh_udp_paths[0] == "/0/0/0/0/0/0"
    assert source.stomp_hex.startswith(r"\x84\x8B")


def test_wordlists_come_from_mhddos(source):
    assert len(source.user_agents) > 100
    assert len(source.referers) > 100
