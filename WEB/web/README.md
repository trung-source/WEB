# TOTP
OTP1.py là chương trình chính của thuật toán TOTP
RSACS1.py là chương trình để sinh khóa bảo mật với thuật toán RSA CSPRBG: Thuật toán RSA bảo mật sinh mã giả trên từng bit
secret1.py là chương trình để tạo QR thông qua khóa và chứa các hàm lấy key, tạo key, reset key

# WEB
Thư mục templates chứa các chương trình html để tạo web
Thư mục static chứa ảnh QR và chứa key để đưa cho User hoặc dùng để kiểm chứng
__init__.py: tạo các dữ liệu khởi tạo
models.py: Tạo các lớp Note và User
auth.py: chứa các hàm liên quan tới đăng ký, đăng nhập, đăng nhập lớp 2
views.py: chứa trang home

