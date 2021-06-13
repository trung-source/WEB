- OTP.py: chương trình chính của thuật toán TOTP
  + Mặc định là thuật toán sẽ đọc secret key của User từ skey.txt từ WEB/web/static/key để tính toán TOTP
  + Để tạo hoặc thay đổi key (không liên quan tới trang web) thì dùng hàm Get_key() thay cho hàm getkey() để lấy secret key do thuật toán tạo ra, dùng hàm reset_key() để reset secret key
- RSACS.py: chương trình chạy của thuật toán RSA CSPRBG: thuật toán RSA bảo mật sinh mã giả trên từng bit
- secret.py: Tạo QR, secret key từ RSACS và HMAC, reset key.
