from . import RSACS1
from . import OTP1
import qrcode
import time
import base64
# import hashlib

def init_secret(p = 509, q = 607, secret = 0):
    # p,q = [9107,6113]

    if secret == 0:
        K = int(RSACS1.genkey(p,q),base=2)                                           # Khóa secret khởi tạo sẽ có chiều dài từ 20 - 64 bytes
        # K2 = hex(K)
        # K3 = hex(K)
        # K2 = hashlib.sha512(K2.encode()).hexdigest()
        # print('  ----  ',len(K2))
        # K3 = OTP.SHA512(K3)
        # print(K2)
        # print(len(K3))
        # print(K3)
        counter = int(time.time()/30) 
        K1 = OTP1.HMAC1(K,counter)                                                   # Khóa secret để share với user (counter = 0)
        K1 = int(K1,base=16)                                                        # Secret key se co chieu dai la 64 bytes
        return K1
    else:
        pass

def sharekey():                                                                     # Khoa chia se
    file = open('WEB\web\static\key\skey.txt','r+')                                   # 
    secret = file.read()
    if secret == '':                                                                # Chưa có khóa thì tạo
        reset_key()                                                                 
    else:
        file.close()
        return secret

def reset_key():                                                                     # Hàm encode khóa
    file = open('WEB\web\static\key\skey.txt','w')  
    secret = init_secret()
    # print(len(hex(int(secret))))
    s = base64.b32encode(bytes(str(secret),'ascii'))                                 # encoding
    s = repr(s)[2:-1]                                                                # Bỏ kí tự b' '
    # print(s)
    file.write(str(s))
    file.close()

def makeqr(k):                                                                       # Tạo QR img
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(k)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save('WEB\web\static\image\QR.png')
    # img.save('Python\OTPfold\Template\QR_1.png')

def main():
    K = sharekey()
    reset_key()
    # print(K)
    K = bytes(K,'ascii')
    
    makeqr(K)
    Q = base64.b32decode(K)
    # print(Q)


if __name__ == "__main__":                                                  # Gọi hàm main  
    start_time = time.time()                                        
    main()  
    end_time = time.time()
    print("%.2f seconds" % (end_time-start_time))
    A = input("Press Enter to Quit")   

