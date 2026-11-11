"""Summarize stored measurements, with no fabricated or extrapolated values."""

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def load_measurements(sources: list[Path]):
    """Select whole valid phases, retaining provenance and anomaly receipts."""
    groups = {}
    durations = {}
    provenance = {}
    anomalies = []
    for source in sources:
        config = json.loads((source / "environment.json").read_text())
        local_groups = defaultdict(list)
        local_durations = {}
        for path in source.glob("timing-*.json"):
            if not re.fullmatch(r"timing-\d+-[01]-\d+", path.stem):
                continue
            _, count, trace, repeat = path.stem.split("-")
            for phase in json.loads(path.read_text()):
                key = (int(count), int(trace), int(repeat), phase["phase"], phase["concurrency"])
                local_durations[key] = phase["seconds"]
        for path in source.glob("raw-*.csv"):
            with path.open() as handle:
                for row in csv.DictReader(handle):
                    if row["phase"] != "warmup":
                        key = (
                            int(row["count"]),
                            int(row["trace"]),
                            int(row["repeat"]),
                            row["phase"],
                            int(row["concurrency"]),
                        )
                        local_groups[key].append(row)
        for key, rows in local_groups.items():
            seconds = local_durations.get(key)
            max_latency = max(float(row["latency_ms"]) for row in rows)
            client_timeout = config["timeout"] + 5
            valid = seconds is not None and max_latency <= 2 * client_timeout * 1000
            if key[3] == "throughput":
                valid = valid and seconds <= config["duration"] + 2 * client_timeout
            if not valid:
                anomalies.append(
                    {
                        "source_run": source.name,
                        "group": list(key),
                        "phase_seconds": seconds,
                        "max_latency_ms": max_latency,
                        "reason": "Incomplete timing or execution interruption beyond timing-integrity bounds",
                    }
                )
            # Never replace an earlier valid phase with a later anomalous one.
            if key not in groups or valid or not provenance[key]["timing_valid"]:
                groups[key] = rows
                durations[key] = seconds
                provenance[key] = {"source_run": source.name, "timing_valid": bool(valid)}
    return groups, durations, provenance, anomalies


def analyze(directory: Path, overlays: list[Path] | None = None):
    sources = [directory] + (overlays or [])
    groups, durations, provenance, anomalies = load_measurements(sources)
    (directory / "timing-anomalies.json").write_text(json.dumps(anomalies, indent=2))
    (directory / "analysis-sources.json").write_text(
        json.dumps([str(p) for p in sources], indent=2)
    )
    summary = []
    for key, rows in sorted(groups.items()):
        count, trace, repeat, phase, concurrency = key
        latency = [float(row["latency_ms"]) for row in rows]
        successful = [row for row in rows if not int(row["error"])]
        opa_samples = [
            float(row["opa_eval_ms"]) for row in successful if float(row["opa_eval_ms"]) > 0
        ]
        seconds = durations.get(key)
        summary.append(
            {
                "count": count,
                "trace": trace,
                "repeat": repeat,
                "phase": phase,
                "concurrency": concurrency,
                **provenance[key],
                "samples": len(rows),
                "elapsed_seconds": seconds,
                "p50_ms": percentile(latency, 0.5),
                "p95_ms": percentile(latency, 0.95),
                "opa_samples": len(opa_samples),
                "opa_p50_ms": percentile(opa_samples, 0.5),
                "opa_p95_ms": percentile(opa_samples, 0.95),
                "throughput_rps": len(rows) / seconds if seconds else None,
                "correctness": mean(int(r["correct"]) for r in rows),
                "error_rate": mean(int(r["error"]) for r in rows),
                "timeout_rate": mean(int(r["timeout"]) for r in rows),
                "average_candidates": mean(float(r["candidate_count"]) for r in successful)
                if successful
                else None,
                "average_matched": mean(float(r["matched_count"]) for r in successful)
                if successful
                else None,
            }
        )
    (directory / "summary.json").write_text(json.dumps(summary, indent=2))
    with (directory / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    # Anomalous phases remain in CSV/JSON and raw data, but do not become plotted performance claims.
    summary = [row for row in summary if row["timing_valid"]]
    charts = directory / "charts"
    charts.mkdir(exist_ok=True)
    plt.rcParams.update(
        {"font.size": 11, "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150}
    )
    # Repeated runs are shown separately; no pooled percentile masquerades as a median run.
    for metric, ylabel in (
        ("p50_ms", "P50 end-to-end latency (ms)"),
        ("p95_ms", "P95 end-to-end latency (ms)"),
        ("opa_p50_ms", "OPA evaluation P50 (ms)"),
    ):
        fig, axis = plt.subplots(figsize=(8, 4.5))
        for trace in (0, 1):
            for repeat in sorted({r["repeat"] for r in summary}):
                rows = [
                    r
                    for r in summary
                    if r["phase"] == "latency" and r["trace"] == trace and r["repeat"] == repeat
                ]
                axis.plot(
                    [r["count"] for r in rows],
                    [r[metric] for r in rows],
                    marker="o",
                    label=f"Trace {'ON' if trace else 'OFF'}, run {repeat}",
                )
        axis.set(
            xscale="log",
            xlabel="Policy count (log scale)",
            ylabel=ylabel,
            title="Sequential HTTP requests · measured samples",
        )
        axis.legend()
        axis.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / f"{metric}.png")
        plt.close(fig)
    for x, name, ylabel in (
        ("count", "throughput-policy", "Completed requests / second"),
        ("concurrency", "throughput-concurrency", "Completed requests / second"),
    ):
        fig, axis = plt.subplots(figsize=(8, 4.5))
        group_field = "concurrency" if x == "count" else "count"
        for group in sorted({r[group_field] for r in summary}):
            rows = sorted(
                [
                    r
                    for r in summary
                    if r["phase"] == "throughput"
                    and r["trace"] == 0
                    and r["repeat"] == 1
                    and r[group_field] == group
                    and r["throughput_rps"] is not None
                ],
                key=lambda r: r[x],
            )
            axis.plot(
                [r[x] for r in rows],
                [r["throughput_rps"] for r in rows],
                marker="o",
                label=f"{group_field}={group}",
            )
        axis.set(xlabel=x, ylabel=ylabel, title="Trace OFF · run 1 · includes failed completions")
        if x == "count":
            axis.set_xscale("log")
        axis.legend()
        axis.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / f"{name}.png")
        plt.close(fig)
    latency = {
        (r["count"], r["trace"]): r for r in summary if r["phase"] == "latency" and r["repeat"] == 1
    }
    counts = sorted(
        {key[0] for key in latency if (key[0], 0) in latency and (key[0], 1) in latency}
    )
    overhead = [100 * (latency[(n, 1)]["p50_ms"] / latency[(n, 0)]["p50_ms"] - 1) for n in counts]
    fig, axis = plt.subplots(figsize=(8, 4.5))
    axis.bar([str(n) for n in counts], overhead, color="#238b8d")
    axis.axhline(0, color="black", linewidth=0.7)
    axis.set(
        xlabel="Policy count",
        ylabel="Change in P50 latency (%)",
        title="Trace ON versus OFF · run 1 · timing noise possible",
    )
    fig.tight_layout()
    fig.savefig(charts / "trace-overhead.png")
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5), sharey=True)
    for axis, metric in zip(axes, ("error_rate", "timeout_rate")):
        for trace in (0, 1):
            for concurrency in (1, 10, 50):
                rows = [
                    r
                    for r in summary
                    if r["phase"] == "throughput"
                    and r["repeat"] == 1
                    and r["trace"] == trace
                    and r["concurrency"] == concurrency
                ]
                axis.plot(
                    [r["count"] for r in rows],
                    [100 * r[metric] for r in rows],
                    marker="o",
                    linestyle="-" if trace else "--",
                    label=f"c={concurrency}, trace={'ON' if trace else 'OFF'}",
                )
        axis.set(
            xscale="log",
            xlabel="Policy count",
            ylabel="Percent of requests",
            title=f"Throughput {metric.replace('_', ' ')} · run 1",
            ylim=(-2, 102),
        )
        axis.grid(alpha=0.2)
    axes[1].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(charts / "error-timeout.png")
    plt.close(fig)
    print(
        f"Summarized {sum(r['samples'] for r in summary)} measured requests in {len(summary)} groups"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--overlay", type=Path, nargs="*", default=[])
    args = parser.parse_args()
    analyze(args.directory, args.overlay)
