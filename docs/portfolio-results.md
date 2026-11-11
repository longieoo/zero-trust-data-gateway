> Recorded evidence from 23 October 2026. The original receipt applies to the pre-publication source tree. Documentation and file selection were subsequently curated for this repository.

# Kết quả kiểm chứng portfolio v5.0

Lượt gate hoàn tất: **23/10/2026 20:33:25 UTC+7**. Đây là thực thi trên máy Windows/Docker local của dự án, không phải kết quả từ Gateway LAN trước đây hoặc GitHub Actions.

Code/config fingerprint: `e607b3b15fefda81422af9d4d7531d165ccdb497495a1546a9b46e97e264b3a0`. Receipt kiểm fingerprint trước và sau lượt chạy, tất cả bước trả exit code 0. Số liệu dưới đây được lấy từ artifacts máy đọc, không nhập số giả định theo mục tiêu.

## Tổng hợp

| Nhóm kiểm chứng | Kết quả | Nguồn |
|---|---|---|
| Pytest, OPA thật cho decision tests | 235/235 đạt; 0 failures; 0 errors; 0 skips | [JUnit](../evidence/pytest.xml) |
| Thời gian JUnit | 111.335 giây | JUnit testsuite time |
| UI xử lý response đến trễ | 4/4 đạt | Node VM tests: `tests/ui/gateway_session.cjs` |
| Docker/HTTPS/mTLS/RLS/recovery | 32/32 đạt | [Live evidence](../evidence/live-validation.json) |
| Trình duyệt Chromium thật | 6/6 đạt | [Browser evidence](../evidence/browser.json) |
| Python dependency audit | 64 packages được báo cáo; 0 lỗ hổng đã biết được trả về | [pip-audit output](../evidence/dependency-audit.json) |
| Code state | Không đổi trong lượt gate | [Verification receipt](../evidence/verification-receipt.json) |

Pytest vẫn ghi 15 deprecation warnings của thư viện test/biểu đồ; chúng không phải lỗi test và không bị giấu khỏi log. Gateway runtime chỉ cài dependencies runtime; Streamlit/matplotlib/pytest/ruff là tùy chọn lab/dev trong metadata package. E2E cũng chạy pip check bên trong container để xác nhận dependencies không thiếu hoặc xung đột.

## Các bước live đã xác nhận

1. **PASS** — synthetic batch idempotence and quality.
2. **PASS** — CA verified TLS readiness.
3. **PASS** — analyst SQL masking and tenant department scope.
4. **PASS** — tenant admin can read unmasked within own tenant.
5. **PASS** — second tenant admin cannot see first tenant.
6. **PASS** — client tenant header cannot override identity.
7. **PASS** — unenrolled TLS client denied before SELECT.
8. **PASS** — certificate-bound token cannot transfer.
9. **PASS** — ABAC department denial before SELECT.
10. **PASS** — historical decision replay matches.
11. **PASS** — audit snapshot is tenant isolated.
12. **PASS** — one signer cannot activate.
13. **PASS** — impact finds admin mask changes on historical snapshots.
14. **PASS** — concurrent activation keeps decision and mask revision consistent.
15. **PASS** — two signed release activation changes obligations.
16. **PASS** — tampered active release fails closed.
17. **PASS** — verified rollback restores original revision.
18. **PASS** — OPA outage fail closed.
19. **PASS** — OPA restart recovers without authorization cache.
20. **PASS** — logout revokes shared session.
21. **PASS** — replayed token rejected after logout.
22. **PASS** — runtime package dependencies are consistent.
23. **PASS** — RLS missing context returns zero.
24. **PASS** — RLS all-scope without tenant returns zero.
25. **PASS** — restrictive tenant gate applies to unfiltered SELECT.
26. **PASS** — RLS tenant AND department.
27. **PASS** — transaction-local context cleared on connection reuse.
28. **PASS** — all three protected tables FORCE RLS.
29. **PASS** — reader SELECT only.
30. **PASS** — session role cannot read business data.
31. **PASS** — two independent session clients observe revocation.
32. **PASS** — live audit backup restores same event page.

## Hiệu năng hiện hành

Closed-loop HTTPS đã kiểm CA/hostname; analyst đọc customers với cap 100 rows, mTLS, tenant/department RLS, SQL masking, shared PostgreSQL session và durable audit bật. 300 mẫu đo, tách riêng 30 warmup. P50/P95 tính bằng nearest rank; RPS = số request đo / elapsed của riêng mức concurrency.

| Concurrent clients | Mẫu đo | P50 (ms) | P95 (ms) | RPS | Lỗi | OPA eval P50 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 100 | 54.85 | 80.62 | 17.21 | 0 | 1.016 |
| 5 | 100 | 95.42 | 142.88 | 49.73 | 0 | 1.254 |
| 10 | 100 | 182.12 | 268.78 | 51.58 | 0 | 1.190 |

Nguồn: [benchmark summary](../evidence/benchmark.json), [raw samples](../evidence/benchmark-samples.csv). Độ trễ tăng khi concurrency tăng; thời gian ngoài OPA còn gồm mạng/proxy, session query, chữ ký, audit và data SELECT. Không gọi throughput này là giới hạn production hoặc tuyến tính theo số core.

Đã thay kết nối PostgreSQL session mới trên mỗi request bằng bounded connection pool; vẫn truy vấn trạng thái phiên trên mỗi lần xác thực. Đã giảm tập dependencies của container và chạy non-root/read-only. Một lần đo trước tuning được lưu ở benchmark-before-session-pool.json/CSV để tham khảo, nhưng dependency và tải host cũng thay đổi nên không dùng hai lần đo để khẳng định mức cải thiện nhân quả chính xác.

Dữ liệu customer hiện gồm 2.000 dòng synthetic được seed idempotent và 3 fixture cũ. Tenant demo: 669 marketing + 334 risk; tenant beta: 667 marketing + 333 risk. Financial/production vẫn là fixture nhỏ. Seed manifest có SQL SHA-256, DQ, counts và fingerprint để đối chiếu lần chạy lại.

## Bảo mật dependency và lỗi đã sửa

Scanner ban đầu báo 126 advisory entries trên 8 packages. Các advisory có thể liên quan và chia sẻ nguyên nhân; đây không phải số lần khai thác đã tái hiện. Đã cập nhật dependency, khóa lại phiên bản và chạy lại tests/E2E/browser. Bản trước và sau được lưu riêng để truy nguyên.

Kiểm thử live đổi active policy đồng thời phát hiện WinError 5 khi Windows/Docker giữ handle đọc file. Đã thêm retry có giới hạn cho cùng thao tác atomic replace, không chuyển sang truncate/write. Unit test kiểm lỗi kéo dài giữ nguyên pointer cũ và dọn temporary file; ca live kiểm revision/mask nhất quán khi active pointer thay đổi.

pip-audit hiện không trả lỗ hổng đã biết cho tập Python được scan. Điều đó không chứng minh không còn lỗ hổng, không bao gồm đầy đủ OS packages của Docker, Nginx/OPA binaries, cloud IAM hoặc pentest ứng dụng.

## Ảnh thực tế

- [Analyst và SQL masking](../evidence/images/01-trusted-masking.png).
- [Replay khớp lịch sử](../evidence/images/02-decision-replay.png).
- [Giao diện di động](../evidence/images/03-mobile.png).
- [Thiết bị không tin cậy bị chặn](../evidence/images/04-untrusted-device.png).
- [Impact analysis qua UI admin](../evidence/images/05-policy-impact.png).

Browser test sử dụng client certificate thật nhưng bỏ kiểm lỗi server CA self-signed của local demo; riêng E2E Python xác minh CA/hostname đầy đủ. Không gộp hai cách cấu hình TLS này thành một tuyên bố.

## Mức hoàn thành so với roadmap

| Hạng mục | Trạng thái hiện tại |
|---|---|
| F01 Bootstrap/doctor/CI | Đã chạy local; có workflow CI, chưa chạy trên remote GitHub |
| F02 Tenant isolation | Đã triển khai và kiểm chứng dữ liệu/audit/token |
| F03 Revision consistency | Đã triển khai single evaluation và live concurrent activation test |
| F04 Replay/impact | Đã triển khai snapshot lịch sử và so sánh; không replay rows |
| F05 Policy lifecycle | Hai khóa, activation/rollback thực; chưa OPA native bundle/GitOps approval service |
| F06 Audit/telemetry | Durable encrypted audit và backup kiểm chứng; chưa OTel collector/SIEM/outbox phân tán |
| F07 Identity/session | Shared session store; chưa OIDC và multi-replica end-to-end |
| F08 Data pipeline | Synthetic upsert/DQ/idempotence; chưa ingest nguồn doanh nghiệp thực |
| F09 Trino | Chưa triển khai |
| F10 Access grant có approval/expiry | Chưa triển khai |
| F11 Recovery/performance | OPA failure/recovery, audit backup, bounded benchmark; chưa disaster recovery toàn nền tảng |
| F12 Portfolio handover | README, architecture, demo, raw evidence và sealed ZIP |

Các phần chưa triển khai được giữ thành hướng phát triển có tiêu chí nghiệm thu, không đặt trạng thái hoàn thành chỉ để tăng quy mô portfolio. Báo cáo học thuật cũ được bảo tồn như snapshot lịch sử; số liệu ở đây chỉ mô tả v5.
