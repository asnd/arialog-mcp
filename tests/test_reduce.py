from arialog_mcp.reduce import RawEvent, cap_events, group_signatures, mask, zscores


def test_mask_collapses_variable_parts():
    a = mask('Cmd(0x45a2f) failed from world 1003 to dev "naa.600508b1001c3d0d" at 10.1.2.3')
    b = mask('Cmd(0x45a21) failed from world 2999 to dev "naa.600508b1001c3d0e" at 10.9.9.9')
    assert a == b
    assert "<IP>" in a and "<HEX>" in a and "<N>" in a


def test_mask_ids_and_timestamps():
    t = mask(
        "vol 5f0d1c2e-7a3b4c5d-8e9f-0a1b2c3d4e5f at 2026-10-07T12:00:01.123Z mac aa:bb:cc:dd:ee:ff"
    )
    assert t == "vol <UUID> at <TS> mac <MAC>"
    assert mask("esx-12 vmnic3 down") == "esx-<N> vmnic<N> down"


def test_group_signatures_counts_hosts_samples():
    evs = [
        RawEvent(1000 + i, f"error code {i} on disk", {"hostname": "h1" if i % 3 else "h2"})
        for i in range(9)
    ] + [RawEvent(5000, "something else", {})]
    groups, distinct = group_signatures(evs, top_n=5, samples=2, max_text_chars=100)
    assert distinct == 2
    assert groups[0].template == "error code <N> on disk" and groups[0].count == 9
    assert groups[0].first_ms == 1000 and groups[0].last_ms == 1008
    assert dict(groups[0].hosts) == {"h1": 6, "h2": 3}
    assert len(groups[0].samples) == 2


def test_zscores_flags_burst_and_skips_flat_or_short():
    z = zscores([1.0] * 20 + [100.0])
    assert z[-1] is not None and z[-1] > 3 and z[0] is not None and z[0] < 1
    assert zscores([5.0] * 20) == [None] * 20
    assert zscores([1.0, 2.0, 3.0]) == [None] * 3


def test_cap_events_by_count_bytes_and_line_length():
    evs = [RawEvent(i, "x" * 500) for i in range(10)]
    kept, why = cap_events(evs, limit=3, max_bytes=10_000, max_text_chars=100)
    assert len(kept) == 3 and "3 events" in (why or "") and len(kept[0].text) == 100
    kept, why = cap_events(evs, limit=10, max_bytes=1_000, max_text_chars=500)
    assert len(kept) < 10 and "byte budget" in (why or "")
    kept, why = cap_events(evs[:2], limit=10, max_bytes=10_000, max_text_chars=500)
    assert len(kept) == 2 and why is None
