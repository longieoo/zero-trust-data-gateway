# Demo, vận hành và bảo vệ phỏng vấn

## Demo 8 phút

1. Mở health và chính sách active: bốn container, phiên bản, revision, chữ ký. Nêu đây là dữ liệu tổng hợp.
2. Analyst tenant demo đọc customers: chỉ marketing, ba cột REDACTED, giới hạn 100 dòng.
3. Beta admin đọc customers: toàn bộ dữ liệu nhìn thấy vẫn thuộc beta; thử X-Tenant-ID không đổi được scope.
4. Analyst đọc financial: DENY, db_queried=false. Trình duyệt không có client certificate cũng bị chặn.
5. Tải lịch sử và Replay: MATCH. Giải thích snapshot lịch sử, không gọi database để dựng lại rows.
6. Dùng admin chạy impact cho candidate mask_admin=true, xem MASK_CHANGED. Kích hoạt với một chữ ký thất bại; ký bằng khóa thứ hai và kích hoạt thành công. Admin đọc lại thấy PII đã che.
7. Rollback về revision trước. Dừng OPA trong script test: 503, db_queried=false; start OPA và đọc lại được. Chỉ dừng service thuộc Compose project đã cấu hình cho runtime này.
8. Logout rồi dùng lại token: 401. Mở receipt, benchmark raw và giới hạn triển khai thay vì chỉ trình chiếu số test.

## Dùng trình duyệt trên máy đang có runtime

Chạy trong source với virtualenv đã kích hoạt:

```powershell
python -m scripts.export_device
```

Lệnh xuất PKCS#12 vào runtime và ghi hướng dẫn/password cục bộ. Không ghi đè file đã xuất. Import client certificate vào kho Personal của trình duyệt/OS; chỉ tin CA demo trên máy dành cho lab. Đóng và mở lại trình duyệt nếu certificate cache chưa cập nhật. Mở https://127.0.0.1:28443 và chọn company-device.

Chứng chỉ v5 được tạo cho localhost/127.0.0.1. Chứng chỉ laptop-02 của Gateway LAN trước đây thuộc runtime khác và không tự hoạt động trên CA mới. Bản hiện tại mặc định bind loopback; muốn mở LAN cần cấu hình SAN đúng, bind address, office networks cụ thể, quản lý khóa và firewall riêng. Không đổi mặc định thành mọi địa chỉ chỉ để bỏ lỗi TLS.

Các ảnh UI tự động trong evidence được chụp bằng Chromium với client certificate thật; browser test bỏ kiểm lỗi CA self-signed của local demo. Kịch bản Python E2E dùng CA verification và hostname verification đầy đủ, không `-k`.

## Phát hành chính sách

Tại repo source, proposal và keys đều nằm trong .gateway. Hai khóa trong bản demo do bootstrap sinh trên cùng máy. Khi vận hành thật, author/reviewer phải giữ khóa riêng và phê duyệt diff/corpus độc lập.

```powershell
python -m scripts.portfolio propose --description "Che PII cho tenant admin" --mask-admin --signer author --key .gateway/maintainers/author.pem
```

Ghi nhận revision được in ra, mở UI bằng admin, dán revision và chạy impact. Sau khi review:

```powershell
python -m scripts.portfolio approve <REVISION_MOI> --signer reviewer --key .gateway/maintainers/reviewer.pem
python -m scripts.portfolio activate <REVISION_MOI> --expected <REVISION_DANG_ACTIVE>
```

Rollback dùng cùng lệnh activate với revision cũ và expected là revision hiện tại. Không sửa JSON đã ký hoặc sửa trực tiếp active pointer để bỏ qua compare-and-swap. Nếu thiếu một chữ ký, chữ ký sai, engine khác, key bị loại khỏi trust set hoặc pointer thay đổi, lệnh phải thất bại.

## Vận hành thường ngày

```powershell
python -m scripts.portfolio doctor --live
python -m scripts.portfolio status
python -m scripts.validate_portfolio
python -m scripts.benchmark_portfolio
python -m scripts.portfolio down
```

`down` không xóa named volume. `validate_portfolio` thực sự kích hoạt/rollback policy và dừng/start OPA, nên dùng deployment demo riêng, không chạy trên production đang phục vụ khách hàng. Mọi sửa policy/OPA trong test được khôi phục trong finally block.

Seed giữ 3 customer fixtures ban đầu và thêm 1.000 customer mỗi tenant. Chạy lại cùng tham số không nhân đôi dữ liệu. Giảm tham số không xóa những dòng đã seed trước đó; đó không phải công cụ reset. Bảng tài chính/production vẫn dùng fixture nhỏ.

Các phiên bản account password, CA, signing keys và encryption key chỉ tồn tại trong runtime được loại khỏi ZIP. Không sao chép runtime cũ đè vào runtime v5. Với database của bản cũ, kiểm backup và schema trước; migration tenant gán dữ liệu cũ vào demo để bảo tồn, nhưng chỉ chạy sau khi đã xác nhận mapping phù hợp. Lệnh `portfolio migrate` chạy migrations idempotent trong project đã cấu hình.

## Quy trình phê duyệt có thời hạn

Đăng nhập `engineer` với chứng chỉ đã đăng ký, chọn production và đọc: nhận ACCESS_APPROVAL_REQUIRED. Gửi yêu cầu có mục đích cụ thể và thời hạn. Mở phiên trình duyệt khác với `data_owner` cùng tenant để phê duyệt. Engineer đọc lại thành công trong phạm vi policy; admin thu hồi hoặc chờ hết hạn, lần đọc tiếp theo bị chặn trước protected SELECT. Không duyệt được yêu cầu của chính mình hoặc tenant khác.

Dùng `python -m scripts.validate_governance` để kiểm chứng cả expiry 60 giây, grant không vượt ABAC và cursor không dùng chéo phiên. Script cần khoảng hơn một phút và chỉ lưu metadata kiểm thử. Trên UI, chọn trang kế tiếp để duyệt từng trang đã lọc/che; đổi resource hoặc đăng nhập lại sẽ xóa cursor cũ.

## Backup và restore

Thực hiện theo [runbook sao lưu và khôi phục](operations.md). CLI sao lưu PostgreSQL, trạng thái Gateway và cấu hình/khóa vào archive mã hóa; khóa giải mã giữ riêng. Tạm dừng proxy/Gateway trong cửa sổ bảo trì ngắn để có snapshot cục bộ nhất quán. Khôi phục vào thư mục mới, thử PostgreSQL trong container cô lập không mạng, đối chiếu nội dung và FORCE RLS; không ghi đè volume đang phục vụ.

Đây là kiểm chứng restore cục bộ, chưa phải chuyển traffic sang site DR, HA đa máy, CA/key rotation tự động hay cam kết RPO/RTO. Sau lỗi khi duyệt/thu hồi quyền, tải lại trạng thái vì commit workflow và response audit không thuộc một giao dịch chung.

## Điểm nên trình bày trong portfolio

- Giải thích vì sao tenant phải là một ràng buộc AND và vì sao FORCE RLS vẫn không chống được superuser/PEP bị chiếm quyền.
- Trình bày race decision–obligations và cách một OPA evaluation cùng revision xử lý nó.
- Phân biệt replay input lịch sử với đọc lại database hiện tại; chỉ rõ UNREPLAYABLE.
- Chỉ ra đánh đổi độ trễ của durable audit/shared session, sử dụng raw samples để giải thích số đo.
- Phân biệt hai khóa mật mã với hai người phê duyệt trong tổ chức.
- Nêu rõ phần đã thực thi, kết quả tự chạy, phần dùng trợ giúp và phần bạn có thể tự sửa/bảo vệ. Không tuyên bố kinh nghiệm production từ một lab.

## Nhánh nâng cấp tiếp theo theo vị trí ứng tuyển

| Nhánh | Phần tiếp theo có giá trị | Điều kiện nghiệm thu |
|---|---|---|
| Data Platform | Trino OPA adapter + semantic parity corpus | Join/subquery/aggregation không bypass row/column policy |
| Backend/Security | OIDC Authorization Code + PKCE | Issuer/audience/JWKS/rotation/outage, không mất cert binding/session revocation |
| Platform/SRE | Audit outbox + telemetry + multi-replica | Sự cố queue/disk/replica, không mất audit, đo revoke trên nhiều node |
| Governance | OIDC identity + external resource owner registry | Ánh xạ tenant/role đúng và không làm mất cơ chế grant hiện có |

Không cần thêm đồng thời tất cả công nghệ trên trước khi bắt đầu ứng tuyển. Bản hiện tại có một câu chuyện xuyên suốt và bằng chứng độc lập để trình bày.
