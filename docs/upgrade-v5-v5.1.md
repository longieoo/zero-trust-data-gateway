# Nâng cấp Zero Trust Data Gateway 5.0 → 5.1

Bản 5.1 tập trung hoàn thiện luồng truy cập dữ liệu từ người dùng đến vận hành: xin quyền, phê duyệt có hạn, đọc theo trang, kiểm toán, thu hồi và khôi phục. Dữ liệu thực nghiệm vẫn là synthetic; không gắn nhãn production hoặc chứng nhận tuân thủ cho một lab cục bộ.

## 1. Siết hợp đồng giữa PDP và SQL

Rà soát phát hiện revision đúng chưa đủ để bảo đảm view plan đúng. Trong bản trước, một envelope gắn đúng revision vẫn có thể bỏ mask cho admin hoặc thay đổi giới hạn dòng đã ký nếu chỉ kiểm tenant và một phần nghĩa vụ.

Evaluator mới đối chiếu độc lập toàn bộ resource, tenant, scope, department, columns, masks và row limit với signed profile. Sai lệch trả INVALID_OPA_RESPONSE trước protected SELECT. Canonical release encoding loại NaN/Infinity, đọc release giới hạn 8 MB và quorum/chữ ký được kiểm kiểu chặt chẽ. Không dùng chữ ký để che giấu giả định rằng Gateway và host vẫn là thành phần tin cậy.

## 2. Cấp quyền có thời hạn

API và Web UI hỗ trợ gửi yêu cầu có mục đích, xem trạng thái, duyệt, thu hồi và hết hạn. Người duyệt phải là admin cùng tenant và khác người yêu cầu. Một grant tồn tại 60–3.600 giây kể từ lúc được duyệt; pending hết hạn sau 24 giờ.

Grant gắn với định danh, tenant, role, department và clearance. Đổi thuộc tính làm grant cũ mất hiệu lực. Compose mặc định yêu cầu grant cho production. Gateway kiểm grant sau OPA ALLOW và trước SELECT, nên phê duyệt không thay ABAC, không đổi tenant và không xóa mask. Live test thử cả grant hợp lệ nhưng phòng ban sai để kiểm chứng điều kiện AND.

Access store dùng SQLite WAL và có giới hạn hàng đợi/dung lượng. Metadata audit ghi loại thao tác và request ID; không ghi mục đích nghiệp vụ hoặc token. Mục đích trong access store là dữ liệu nhạy cảm cục bộ, phải bảo vệ và sao lưu mã hóa.

## 3. Catalog và phân trang an toàn

Catalog công bố metadata tài nguyên, PII columns, page cap và nhu cầu phê duyệt cho danh tính đã xác minh. Nó không tự cấp quyền đọc.

Dữ liệu hỗ trợ keyset pagination theo ID. Cursor HMAC có TTL 10 phút, gắn với subject đầy đủ, session, resource, policy revision và page size. Đổi tài khoản/phiên/policy hoặc sửa cursor bị chặn; mỗi trang thực hiện lại kiểm tra quyền, grant, SQL masking và RLS. Không dùng OFFSET để duyệt dữ liệu lớn và không giữ transaction qua nhiều HTTP request.

UI có nút trang tiếp theo, hủy kết quả đến trễ khi đổi phiên/resource và chỉ dựng nội dung dữ liệu bằng DOM textContent. Token nằm trong bộ nhớ trang. Phân trang không phải snapshot nhất quán của toàn bộ database; dữ liệu thay đổi giữa các request có thể ảnh hưởng trang sau.

## 4. Readiness và lịch sử quyết định

Health bao gồm OPA, policy, business DB, audit, session store và access store. Audit/access probe thực sự thử giao dịch ghi rồi rollback; một file chỉ đọc không được coi là sẵn sàng ghi.

Replay phân loại snapshot thiếu/sai kiểu/corrupt ciphertext thành UNREPLAYABLE, không tạo MATCH giả và không đọc lại business rows. Input audit và pagination được giới hạn ngay trong store, không chỉ ở HTTP layer. Replay tái lập quyết định OPA đã ghi; không giả lập lại approval/session lịch sử hoặc dữ liệu đã đọc trước đây.

## 5. Sao lưu mã hóa và khôi phục thử

CLI mới tạo archive AES-GCM chứa pg_dump custom, Gateway state và cấu hình/chứng chỉ/signed releases. Backup key tách riêng. Trong cửa sổ bảo trì ngắn, chỉ proxy/Gateway của đúng Compose project bị tạm dừng; trạng thái chạy trước đó được phục hồi kể cả khi backup lỗi.

Restore chỉ ghi vào thư mục mới, xác thực archive trước khi trích xuất, kiểm SHA-256/size/mode và từ chối path traversal. PostgreSQL khôi phục trong container dùng network none, không public port và không ghi volume đang chạy. Đối chiếu số dòng, fingerprint dữ liệu và FORCE RLS của ba bảng.

Khôi phục thử thành công không đồng nghĩa đã triển khai site DR hoặc đạt RPO/RTO cụ thể. Promotion, đồng bộ database role credentials, key rotation và routing chuyển site vẫn là công việc vận hành có kế hoạch.

## 6. Tính tái lập trên Windows và Linux

.gitattributes quy định LF để shell init và engine fingerprint không lệch do CRLF. Compose project có thể cấu hình để runtime mới không dùng nhầm volume/credential cũ. Trên POSIX, material riêng tư bị hạn chế quyền; subtree cấu hình được bind-mount cho UID 10001 đọc được. Runtime, credentials, backup, private keys và database không được đưa vào Git hoặc ZIP source.

CI chạy Python/Node regressions, fresh Docker deployment, live mTLS/RLS/recovery, governance/expiry, backup/restore, browser, benchmark và dependency audit. Final gate ghi fingerprint trước/sau để không dùng kết quả của source đã thay đổi.

## 7. Cách kiểm chứng

```bash
python -m scripts.portfolio init
python -m scripts.portfolio up
python -m scripts.portfolio doctor --live
python -m scripts.verify_release
```

Cài locked Python dependencies, OPA 1.4.2, Node/Playwright trước khi chạy. Final gate có bài test chờ grant 60 giây hết hạn; thời gian này là quan sát thật, không chỉnh clock máy chủ.

Số test, số live checks, benchmark và trạng thái gate lấy từ [báo cáo kết quả](portfolio-results.md) cùng artifacts dưới evidence. Không hardcode số test mục tiêu vào điều kiện PASS. Kết quả v5.0 ngày 23/10 được lưu riêng dưới history; không dùng làm số liệu mới của v5.1.

## 8. Giới hạn còn lại

- Gateway/ingress/host vẫn được tin cậy; RLS không chống được Gateway đã chiếm quyền với credential chọn context.
- SQLite audit/access store là single-host; chưa có distributed outbox, retention scheduler hoặc KMS rotation.
- Workflow commit và response audit là hai giao dịch; sau 503 phải đọc lại trạng thái, không giả định rollback.
- Client key là file; chưa TPM, MDM telemetry hay cơ chế attestation thiết bị.
- Hai khóa demo cùng máy thể hiện quorum mật mã; chưa thể hiện hai người kiểm soát độc lập.
- OIDC, Trino authorization adapter, HA nhiều Gateway host và site DR chưa được triển khai.

Các giới hạn trên có phạm vi rõ ràng để bảo vệ portfolio: chứng minh luồng đã chạy được, giải thích được đánh đổi và biết tiêu chí cần có trước khi đưa lên môi trường thực.
