# Kết quả kiểm chứng v5.1.0

Tạo từ lượt final gate kết thúc ngày **2026-11-13**. Đây là thực thi Windows/Docker cục bộ, dữ liệu synthetic. CI trên GitHub là một lượt thực thi riêng, phải xem trạng thái workflow của đúng commit; không lấy kết quả local để gọi là CI PASS.

## Phạm vi và kết quả

| Nhóm | Kết quả thực thi | Minh chứng |
|---|---|---|
| Python với OPA thật | 359 passed, 0 failed/error, 0 platform skip; 122.992 giây | [JUnit](../evidence/pytest.xml) |
| Docker, mTLS, RLS, policy/recovery | 32/32 PASS | [Live JSON](../evidence/live-validation.json) |
| Phê duyệt, expiry và pagination | 22/22 PASS | [Governance JSON](../evidence/governance.json) |
| Trình duyệt thật | 10/10 PASS; Playwright Chromium | [Browser JSON](../evidence/browser.json) |
| Sao lưu và khôi phục cô lập | 34 file, PostgreSQL restored, SQLite integrity OK | [Recovery JSON](../evidence/recovery.json) |
| Snapshot kiểm toán khôi phục | 818 snapshot xác thực/giải mã; nội dung không công bố | Recovery JSON |
| Dependency audit Python | 64 packages; 0 lỗ hổng đã biết được trả về tại thời điểm quét | [pip-audit JSON](../evidence/dependency-audit.json) |
| Source trong lượt gate | Không đổi; mọi bước exit 0 | [Receipt](../evidence/verification-receipt.json) |

Source/config SHA-256: `9f85738a5121953af22d8f2106b2f204e61e0698ca865c34ce24e64e8d77c7cd`. Receipt bao phủ code/config/test, không bao phủ mọi tài liệu hoặc chứng minh nguồn chưa bị administrator thay. Log đầy đủ lưu cục bộ và trong CI artifact; các file log không được đưa vào source package.

Chỉ ca kiểm tra Windows file-sharing được phép SKIP trên Linux. Mọi skip khác hoặc lỗi test làm bước tổng hợp thất bại; số pass luôn trừ số skip thực tế, không đổi SKIP thành PASS.

## Các kiểm chứng mới

- PASS — production read requires approval before SELECT.
- PASS — access request accepted for verified identity.
- PASS — requester cannot approve a request.
- PASS — other tenant admin cannot approve request.
- PASS — access request accepted for verified identity.
- PASS — admin cannot self approve.
- PASS — independent tenant owner approves.
- PASS — approved engineer reads production under normal ABAC.
- PASS — owner revokes grant.
- PASS — revoked grant denies next protected SELECT.
- PASS — access request accepted for verified identity.
- PASS — independent owner approves financial workflow record.
- PASS — approved workflow cannot bypass an ABAC deny.
- PASS — access request accepted for verified identity.
- PASS — short lived grant accepted.
- PASS — analyst first page enforces SQL masking and department.
- PASS — first page provides continuation.
- PASS — second page has disjoint authorized rows.
- PASS — tampered cursor rejected before SELECT.
- PASS — cursor cannot move to another identity or session.
- PASS — cursor cannot move to another tenant.
- PASS — real expiry denies next request before SELECT.

Live baseline còn kiểm tenant không thể ghi đè bằng header, certificate-bound token, SQL masking, hai chữ ký, activation/rollback, policy tamper, OPA outage/recovery, logout/replay, FORCE RLS, SELECT-only role và xóa transaction-local context. `db_queried=false` chỉ nói chưa chạy protected business SELECT; các store xác thực/kiểm toán vẫn có thể được đọc/ghi.

## Khôi phục và dữ liệu

Backup thực sự tạm dừng proxy/Gateway của deployment riêng, rồi phục hồi chúng. Restore chạy PostgreSQL với network none, không host port và không ghi live volumes. So sánh nội dung business tables/session table; kiểm ENABLE/FORCE RLS, tenant/scope policies, reader/session privileges và truy vấn không bối cảnh trả 0 dòng. SQLite audit/access được integrity check và đối chiếu logical fingerprints; mọi snapshot được xác thực với khóa khôi phục. Đây là restore cục bộ, chưa phải promotion DR/HA hoặc số đo RPO/RTO.

Số dòng customer thực tế: **2003**; financial: **2**; production: **2**. Seed giữ 3 customer fixtures và tạo 1.000 dòng mỗi tenant, chạy lặp không nhân bản.

## Benchmark hiện hành

300 mẫu đo, 30 warmup tách riêng. Closed-loop HTTPS kiểm CA/hostname, analyst đọc customers, cap 100 rows, audit ON và shared PostgreSQL sessions. P50/P95 theo nearest rank; RPS bằng số request đo chia elapsed của từng mức concurrency.

| Concurrent clients | Mẫu | P50 ms | P95 ms | RPS | Lỗi | OPA P50 ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 100 | 52.00 | 96.77 | 17.88 | 0 | 1.138 |
| 5 | 100 | 95.22 | 143.52 | 50.32 | 0 | 1.163 |
| 10 | 100 | 193.21 | 267.56 | 49.17 | 0 | 1.159 |

Nguồn: [summary](../evidence/benchmark.json), [raw CSV](../evidence/benchmark-samples.csv). Script sinh báo cáo đối chiếu lại phân vị từ CSV, không chép số mục tiêu. Đây là đo trên một máy có thể chia sẻ CPU/IO với dự án khác; không phải production capacity, open-loop load test hay bằng chứng nhân quả so sánh với các bản cũ.

## Giới hạn và lịch sử

Gateway/host là trusted PEP; khóa client là file; risk model heuristic. Audit/access SQLite single-host, workflow và response audit không atomic, chưa OIDC/Trino/TPM/KMS/outbox phân tán hoặc multi-host failover. Replay tái lập quyết định/obligations, không tái lập business rows hay authorization session/grant lịch sử. Dependency audit không thay thế container image scan, pentest hoặc chứng nhận tuân thủ.

Ảnh browser dùng chứng chỉ client thật và bỏ cảnh báo CA demo ở browser context. Python live/benchmark xác minh CA và hostname đầy đủ. [Ảnh thực nghiệm](../evidence/images/) và [security review](security-review.md) mô tả phạm vi cụ thể. Kết quả ngày 23/10/2026 nằm riêng trong [history](../evidence/history/2026-10-23/README.md), không dùng làm số mới.

Pytest ghi nhận 15 deprecation warnings; không có failure/error/skip trong lượt Windows này. pip-audit khuyến nghị bổ sung hash toàn bộ dependency lock; file hiện tại khóa phiên bản, chưa dùng --require-hashes.
