from arialog_mcp.reduce import (
    RawEvent,
    cap_events,
    group_signatures,
    mask,
    sanitize_event,
    time_bins,
    zscores,
)


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


def test_time_bins_sorts_fills_gaps_and_marks_partial_edges():
    # window 1_500..10_500 ms, width 2_000, VRLI bins epoch-aligned, sparse and newest first
    tb = time_bins([(8_000, 3.0), (2_000, 5.0)], start_ms=1_500, end_ms=10_500, width_ms=2_000)
    assert [(b.start_ms, b.count, b.partial) for b in tb] == [
        (0, 0.0, True),
        (2_000, 5.0, False),
        (4_000, 0.0, False),
        (6_000, 0.0, False),
        (8_000, 3.0, False),
        (10_000, 0.0, True),
    ]


def test_time_bins_follows_vrli_phase_and_keeps_unexpected_bins():
    tb = time_bins([(1_500, 1.0), (99_000, 2.0)], start_ms=1_500, end_ms=5_500, width_ms=2_000)
    assert [b.start_ms for b in tb] == [1_500, 3_500, 99_000]
    assert [b.partial for b in tb] == [False, False, True]
    assert time_bins([], start_ms=0, end_ms=4_000, width_ms=2_000)[1].count == 0.0


def test_sensitive_credentials_are_redacted_from_event_text_and_fields():
    event = sanitize_event(
        RawEvent(
            1,
            'password="topsecret" Authorization: Bearer abc123 https://u:p@host',
            {"api_token": "private", "hostname": "node-a"},
        )
    )
    assert "topsecret" not in event.text
    assert "abc123" not in event.text
    assert "u:p" not in event.text
    assert event.fields == {"api_token": "[redacted]", "hostname": "node-a"}


def test_byte_budget_counts_event_fields():
    events = [RawEvent(1, "short", {"description": "x" * 1000})]
    kept, reason = cap_events(events, limit=10, max_bytes=200, max_text_chars=1000)
    assert kept == []
    assert reason == "byte budget of 200 reached"
