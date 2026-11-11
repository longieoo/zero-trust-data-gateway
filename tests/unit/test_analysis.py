import csv
import json

import pytest

from benchmark.analyze import load_measurements, percentile


def write_phase(directory, latency, duration, sample, error=0):
    directory.mkdir()
    (directory / "environment.json").write_text(json.dumps({"timeout": 10, "duration": 60}))
    (directory / "timing-100-1-1.json").write_text(
        json.dumps([{"phase": "throughput", "concurrency": 50, "seconds": duration}])
    )
    row = {
        "count": 100,
        "trace": 1,
        "repeat": 1,
        "phase": "throughput",
        "concurrency": 50,
        "sample": sample,
        "latency_ms": latency,
        "error": error,
    }
    with (directory / "raw-100-1-1.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)


def test_repair_replaces_whole_interrupted_phase_and_keeps_real_timeouts(tmp_path):
    interrupted, repaired = tmp_path / "interrupted", tmp_path / "repaired"
    write_phase(interrupted, 2950000, 2955, "interrupted")
    write_phase(repaired, 15001, 75, "genuine-timeout", error=1)
    groups, durations, provenance, anomalies = load_measurements([interrupted, repaired])
    key = (100, 1, 1, "throughput", 50)
    assert len(groups[key]) == 1
    assert groups[key][0]["sample"] == "genuine-timeout"
    assert groups[key][0]["error"] == "1"
    assert durations[key] == 75
    assert provenance[key] == {"source_run": "repaired", "timing_valid": True}
    assert len(anomalies) == 1
    assert anomalies[0]["source_run"] == "interrupted"


def test_later_bad_run_cannot_replace_valid_phase(tmp_path):
    valid, bad = tmp_path / "valid", tmp_path / "bad"
    write_phase(valid, 100, 60.1, "valid")
    write_phase(bad, 700000, 734, "bad")
    groups, _, provenance, _ = load_measurements([valid, bad])
    key = (100, 1, 1, "throughput", 50)
    assert groups[key][0]["sample"] == "valid"
    assert provenance[key]["timing_valid"]


def test_percentiles_use_documented_linear_interpolation():
    assert percentile([4, 1, 3, 2], 0.5) == 2.5
    assert percentile([4, 1, 3, 2], 0.95) == pytest.approx(3.85)
    assert percentile([], 0.5) is None


def test_reanalysis_ignores_generated_anomaly_report(tmp_path):
    run = tmp_path / "run"
    write_phase(run, 100, 60.1, "valid")
    first = load_measurements([run])
    (run / "timing-anomalies.json").write_text(json.dumps(first[3]))
    assert load_measurements([run]) == first
