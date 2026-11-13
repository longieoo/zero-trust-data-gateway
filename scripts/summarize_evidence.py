"""Generate the current results page from one successful, unchanged final gate."""

import csv
import json
from datetime import datetime
from xml.etree import ElementTree

from scripts.benchmark_portfolio import percentile
from scripts.verify_release import ROOT, fingerprint


def junit_summary(suite):
    if suite is None or any(int(suite.get(key, "0")) for key in ("errors", "failures")):
        raise ValueError("Python suite has failures or errors")
    skipped = [case for case in suite.findall("testcase") if case.find("skipped") is not None]
    for case in skipped:
        if (
            case.get("classname") != "tests.unit.test_releases"
            or case.get("name") != "test_atomic_replace_retries_transient_windows_sharing_violation"
            or case.find("skipped").get("message") != "Windows file sharing semantics"
        ):
            raise ValueError("Unexpected skipped Python test")
    total = int(suite.get("tests", "0"))
    if total < 1 or len(skipped) > 1 or int(suite.get("skipped", "0")) != len(skipped):
        raise ValueError("Invalid JUnit counts")
    return {"passed": total - len(skipped), "skipped": len(skipped)}


def main():
    evidence = ROOT / "evidence"

    def read(name):
        return json.loads((evidence / name).read_text(encoding="utf-8"))

    receipt = read("verification-receipt.json")
    if not receipt["passed"] or not receipt["source_unchanged"]:
        raise ValueError("A successful final gate is required")
    if receipt["source_sha256"] != fingerprint()[0]:
        raise ValueError("Source changed after the recorded gate")
    steps = {row["step"]: row for row in receipt["steps"]}
    required = {
        "lint",
        "pytest",
        "ui-unit",
        "compose",
        "live",
        "governance",
        "backup",
        "restore",
        "browser",
        "benchmark",
        "dependency-audit",
    }
    if set(steps) != required or any(row["returncode"] for row in steps.values()):
        raise ValueError("Incomplete final gate")
    suite = ElementTree.parse(evidence / "pytest.xml").getroot().find("testsuite")
    python_result = junit_summary(suite)
    live, governance, browser = (
        read(name) for name in ("live-validation.json", "governance.json", "browser.json")
    )
    for report in (live, governance, browser):
        if not report["complete"] or not all(row["pass"] for row in report["checks"]):
            raise ValueError("Incomplete live/browser evidence")
    recovery, benchmark, audit = (
        read(name) for name in ("recovery.json", "benchmark.json", "dependency-audit.json")
    )
    if recovery.get("restored") is not True or recovery["state"]["authenticated_snapshots"] < 1:
        raise ValueError("Restore must include authenticated historical snapshots")
    if any(row.get("vulns") for row in audit["dependencies"]):
        raise ValueError("Dependency audit reported vulnerabilities")
    samples = list(csv.DictReader((evidence / "benchmark-samples.csv").open(newline="")))
    if sum(row["phase"] == "measured" for row in samples) != benchmark["measured_samples"]:
        raise ValueError("Benchmark sample count mismatch")
    table = []
    for run in benchmark["runs"]:
        rows = [
            row
            for row in samples
            if row["phase"] == "measured" and int(row["concurrency"]) == run["concurrency"]
        ]
        times = [float(row["latency_ms"]) for row in rows]
        if (
            len(rows) != run["requests"]
            or run["errors"]
            or any(row["valid"] != "True" for row in rows)
        ):
            raise ValueError("Benchmark correctness mismatch")
        for fraction, key in ((0.5, "p50_ms"), (0.95, "p95_ms")):
            if abs(percentile(times, fraction) - run[key]) > 1e-6:
                raise ValueError("Benchmark percentile mismatch")
        table.append(
            f"| {run['concurrency']} | {run['requests']} | {run['p50_ms']:.2f} | "
            f"{run['p95_ms']:.2f} | {run['rps']:.2f} | {run['errors']} | "
            f"{run['opa_eval_p50_ms']:.3f} |"
        )
    date = datetime.fromisoformat(receipt["executed_at"]).date().isoformat()
    checks = "\n".join(f"- PASS — {row['name']}." for row in governance["checks"])
    text = f"""# Kết quả kiểm chứng v5.1.0

Tạo từ lượt final gate kết thúc ngày **{date}**. Đây là thực thi Windows/Docker cục bộ, dữ liệu synthetic. CI trên GitHub là một lượt thực thi riêng, phải xem trạng thái workflow của đúng commit; không lấy kết quả local để gọi là CI PASS.

## Phạm vi và kết quả

| Nhóm | Kết quả thực thi | Minh chứng |
|---|---|---|
| Python với OPA thật | {python_result["passed"]} passed, 0 failed/error, {python_result["skipped"]} platform skip; {float(suite.get("time")):.3f} giây | [JUnit](../evidence/pytest.xml) |
| Docker, mTLS, RLS, policy/recovery | {len(live["checks"])}/{len(live["checks"])} PASS | [Live JSON](../evidence/live-validation.json) |
| Phê duyệt, expiry và pagination | {len(governance["checks"])}/{len(governance["checks"])} PASS | [Governance JSON](../evidence/governance.json) |
| Trình duyệt thật | {len(browser["checks"])}/{len(browser["checks"])} PASS; {browser["browser"]} | [Browser JSON](../evidence/browser.json) |
| Sao lưu và khôi phục cô lập | {recovery["verified_files"]} file, PostgreSQL restored, SQLite integrity OK | [Recovery JSON](../evidence/recovery.json) |
| Snapshot kiểm toán khôi phục | {recovery["state"]["authenticated_snapshots"]} snapshot xác thực/giải mã; nội dung không công bố | Recovery JSON |
| Dependency audit Python | {len(audit["dependencies"])} packages; 0 lỗ hổng đã biết được trả về tại thời điểm quét | [pip-audit JSON](../evidence/dependency-audit.json) |
| Source trong lượt gate | Không đổi; mọi bước exit 0 | [Receipt](../evidence/verification-receipt.json) |

Source/config SHA-256: `{receipt["source_sha256"]}`. Receipt bao phủ code/config/test, không bao phủ mọi tài liệu hoặc chứng minh nguồn chưa bị administrator thay. Log đầy đủ lưu cục bộ và trong CI artifact; các file log không được đưa vào source package.

Chỉ ca kiểm tra Windows file-sharing được phép SKIP trên Linux. Mọi skip khác hoặc lỗi test làm bước tổng hợp thất bại; số pass luôn trừ số skip thực tế, không đổi SKIP thành PASS.

## Các kiểm chứng mới

{checks}

Live baseline còn kiểm tenant không thể ghi đè bằng header, certificate-bound token, SQL masking, hai chữ ký, activation/rollback, policy tamper, OPA outage/recovery, logout/replay, FORCE RLS, SELECT-only role và xóa transaction-local context. `db_queried=false` chỉ nói chưa chạy protected business SELECT; các store xác thực/kiểm toán vẫn có thể được đọc/ghi.

## Khôi phục và dữ liệu

Backup thực sự tạm dừng proxy/Gateway của deployment riêng, rồi phục hồi chúng. Restore chạy PostgreSQL với network none, không host port và không ghi live volumes. So sánh nội dung business tables/session table; kiểm ENABLE/FORCE RLS, tenant/scope policies, reader/session privileges và truy vấn không bối cảnh trả 0 dòng. SQLite audit/access được integrity check và đối chiếu logical fingerprints; mọi snapshot được xác thực với khóa khôi phục. Đây là restore cục bộ, chưa phải promotion DR/HA hoặc số đo RPO/RTO.

Số dòng customer thực tế: **{recovery["counts"]["customers"]}**; financial: **{recovery["counts"]["financial"]}**; production: **{recovery["counts"]["production"]}**. Seed giữ 3 customer fixtures và tạo 1.000 dòng mỗi tenant, chạy lặp không nhân bản.

## Benchmark hiện hành

{benchmark["measured_samples"]} mẫu đo, {benchmark["warmup_samples"]} warmup tách riêng. Closed-loop HTTPS kiểm CA/hostname, analyst đọc customers, cap 100 rows, audit ON và shared PostgreSQL sessions. P50/P95 theo nearest rank; RPS bằng số request đo chia elapsed của từng mức concurrency.

| Concurrent clients | Mẫu | P50 ms | P95 ms | RPS | Lỗi | OPA P50 ms |
|---|---:|---:|---:|---:|---:|---:|
{chr(10).join(table)}

Nguồn: [summary](../evidence/benchmark.json), [raw CSV](../evidence/benchmark-samples.csv). Script sinh báo cáo đối chiếu lại phân vị từ CSV, không chép số mục tiêu. Đây là đo trên một máy có thể chia sẻ CPU/IO với dự án khác; không phải production capacity, open-loop load test hay bằng chứng nhân quả so sánh với các bản cũ.

## Giới hạn và lịch sử

Gateway/host là trusted PEP; khóa client là file; risk model heuristic. Audit/access SQLite single-host, workflow và response audit không atomic, chưa OIDC/Trino/TPM/KMS/outbox phân tán hoặc multi-host failover. Replay tái lập quyết định/obligations, không tái lập business rows hay authorization session/grant lịch sử. Dependency audit không thay thế container image scan, pentest hoặc chứng nhận tuân thủ.

Ảnh browser dùng chứng chỉ client thật và bỏ cảnh báo CA demo ở browser context. Python live/benchmark xác minh CA và hostname đầy đủ. [Ảnh thực nghiệm](../evidence/images/) và [security review](security-review.md) mô tả phạm vi cụ thể. Kết quả ngày 23/10/2026 nằm riêng trong [history](../evidence/history/2026-10-23/README.md), không dùng làm số mới.
"""
    (ROOT / "docs/portfolio-results.md").write_bytes(text.encode("utf-8"))
    print("Current evidence reconciled; results page regenerated.")


if __name__ == "__main__":
    main()
