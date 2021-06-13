#-------------------------------------TOTP ALGORITHM------------------------------------------------------------------#

import hashlib                                                              # Thư viện cho hàm Hash: SHA-1,SHA-256,SH-384,MD5,...
import time
import base64
import RSACS
import secret

# Keyed-Hashing for Message Authentication - RFC2104 - HMA-SHA-1
# HOTP: An HMAC-Based One-Time Password Algorithm - RFC4226 - HOTP
# TOTP: Time-Based One-Time Password Algorithm - RFC 6238 - TOTP
# Randomness Requirements for Security - RFC 4086 - Secret Key





#---------------------------------------------------HMAC Function----------------------------------------------------------#


def HMAC(K,tm):                                                         # HMAC sử dụng SHA512 trong thư viện hashlib theo bài báo rfc2104
    ipad = int('0x36' + '36'*127,base=16)                                # the byte 0x36 repeated B times (B=64)
    opad = int('0x5C' + '5C'*127,base=16)                                # the byte 0x5C repeated B times (B=64)

    K = int(bin(K) + '0'*(128*8-len(bin(K)[2:])),base=2)                 # Gắn thêm 0 vào cuối cho đủ 64 byte theo bước 1 của thuật toán HMA
    K1 = K^ipad                                                         # Cộng XOR với ipad theo bước 2 của thuật toán HMA
    tm = str(hex(tm))[2:]                                               # Chuyển về string và cắt bỏ phần 0x
    if len(tm) < 16:                                                    # Thêm bit 0 vào trước cho đủ 8 byte để gắn vào khóa K
        tm = '0'*(16-len(tm)) + tm                                      # Theo thuật toán HOTP thì counter sẽ là 8 bytes 
    K1 = str(hex(K1)) + tm                                              # Nối counter vào theo thuật bước 3 của thuật toán HMA
   
    H1 = hashlib.sha512(K1.encode()).hexdigest()                        # Đưa qua hàm hash SHA1 có trong thư viện hashlib theo bước 4 của thuật toán HMA
                                                                        # Hàm hexdigest biểu diễn một byte thành một ký tự hex

    K2 = K^opad                                                         # Cộng XOR với opad theo bước 5 của thuật toán HMA

    K2 = str(hex(K2)) + H1                                              # Nối H1 vào K2 theo bước 6 của thuật toán HMA

    H2 = hashlib.sha512(K2.encode()).hexdigest()                        # Đưa qua hàm hash SHA1 theo bước 7 của thuật toán HMA và trả về kết quả

    H2 = '0x' + H2
    return H2


def HMAC1(K,tm):                                                        # HMAC sử dụng hàm SHA512 xây dựng theo bài báo rfc 2104
    ipad = int('0x36' + '36'*127,base=16)                               # the byte 0x36 repeated B times (B=128)
    opad = int('0x5C' + '5C'*127,base=16)                               # the byte 0x5C repeated B times (B=128)

    K = int(bin(K) + '0'*(128*8-len(bin(K)[2:])),base=2)                # Gắn thêm 0 vào cuối cho đủ 128 byte theo bước 1 của thuật toán HMA
    K1 = K^ipad                                                         # Cộng XOR với ipad theo bước 2 của thuật toán HMA
    tm = str(hex(tm))[2:]                                               # Chuyển về string và cắt bỏ phần 0x
    if len(tm) < 16:                                                    # Thêm bit 0 vào trước cho đủ 8 byte để gắn vào khóa K
        tm = '0'*(16-len(tm)) + tm                                      # Theo thuật toán HOTP thì counter sẽ là 8 bytes 
    K1 = str(hex(K1)) + tm                                              # Nối counter vào theo thuật bước 3 của thuật toán HMA
   
    H1 = SHA512(K1)                                                     # Đưa qua hàm hash SHA1 có trong thư viện hashlib theo bước 4 của thuật toán HMA
                                                                        # Hàm hexdigest biểu diễn một byte thành một ký tự hex

    K2 = K^opad                                                         # Cộng XOR với opad theo bước 5 của thuật toán HMA

    K2 = str(hex(K2)) + H1[2:]                                          # Nối H1 vào K2 theo bước 6 của thuật toán HMA
    H2 = SHA512(K2)                                                      # Đưa qua hàm hash SHA512 theo bước 7 của thuật toán HMA và trả về kết quả
    return H2



#---------------------------------------------------SHA512 Function----------------------------------------------------------#


def SHA512(msg):                                                        # Hàm sha512 tạo ra theo bài báo rfc6234
    msg = str(bin(int(msg,base=16)))                                    # Đưa về dạng string binary
    if len(msg) < 2**128:                                               # Padding với bản tin đầu vào của msg
        l1 = bin(len(msg) - 2)                                          # Quy đổi chiều dài của msg ra nhị phân
        msg += '1'                                                      # Nối thêm bit 1 ở cuối msg                                    
        l2 = (len(msg)-2) % 1024                                        # (a+b) mod n = (a mod n + b mod n) mod n
        # print(l2)
        if l2 > 896:                                                    # p là giá trị dương nhỏ nhất sao cho (l+1+p) mod 1024 = 896
            p = 1024 + 896  - l2                                        # Ở đây, l2 = l + 1                                               
        else:
            p = 896 - l2

        msg += '0'*p                                                    # Nối thêm p bit 0 vào msg để block cuối của msg có chiều dài là 896 bit
        msg += '0'*(130-len(l1)) +  str(l1[2:])                         # Nối thêm bit biểu diễn chiều dài của msg ban đầu để block cuối gồm 1024 bit

    if len(msg) >= 2**128:
        raise Exception("Ban tin dau vao vuot qua chieu dai quy dinh.")

    # Giá trị hash khởi tạo
    H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]

    # Khởi tạo các giá trị hằng số vòng 
    k = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

    msg = msg[2:]                                                           # Bỏ 2 kí tự string '0b'
    msg2 = []
    for i in range(0,len(msg),1024):                                        # Tạo các block 1024 bit từ msg và đưa vào msg2
        msg2.append(msg[i:i+1024])
    
    msg3 = []                                                               # msg3[i] sẽ chứa các khối 64 bit tách từ khối 1024 bit của msg2
    for i in range(len(msg2)):                                              # msg3 sẽ chứa các block 1024 bit
        msg3.append([])
        for j in range(0,len(msg2[0]),64):
            l = msg2[i][j:j+64]
            msg3[i].append(l) 

    for i in range(len(msg3)):                                              # Quy đổi từ string ra int
        for j in range(len(msg3[0])):
            msg3[i][j] = int('0b' + msg3[i][j],base=2)

    for i in range(len(msg3)):                                              # Truy cập từng khối 1024 bit                      
        W = msg3[i]                                                         # Chuẩn bị cho đầu vào W
        for t in range(16,80):
            l = (SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16]) & 0xFFFFFFFFFFFFFFFF
            W.append(l)
        # print(msg3)
        a,b,c,d,e,f,g,h = H                                                 # Khởi tạo các biến
        for t in range(0,80):                                               # Thực hiện tính toán hàm băm
            T1 = h + BSIG1(e) + CH(e,f,g) + k[t] + W[t]
            T2 = BSIG0(a) + MAJ(a,b,c)
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFFFFFFFFFF

        # Tính lại các giá trị H[i] kế tiếp
        H[0] = (a + H[0]) & 0xFFFFFFFFFFFFFFFF                                  # ngoài cách dùng AND, ta có thể mod 2**64
        H[1] = (b + H[1]) & 0xFFFFFFFFFFFFFFFF
        H[2] = (c + H[2]) & 0xFFFFFFFFFFFFFFFF
        H[3] = (d + H[3]) & 0xFFFFFFFFFFFFFFFF
        H[4] = (e + H[4]) & 0xFFFFFFFFFFFFFFFF
        H[5] = (f + H[5]) & 0xFFFFFFFFFFFFFFFF
        H[6] = (g + H[6]) & 0xFFFFFFFFFFFFFFFF
        H[7] = (h + H[7]) & 0xFFFFFFFFFFFFFFFF
        # N = [(hex(int(H[i]))) for i in range(0,8)]
        # O = [len(hex(int(H[i]))) for i in range(0,8)]
    F = '0x'                                                                    # Chứa giá trị cuối của 1 block khi qua hàm băm
    for i in range(len(H)):
        F = F + '0'* (16-len(hex(H[i])[2:])) + str(hex(H[i])[2:])               # Bổ sung các string '0' vào phần đầu của các H[i] dưới 16 byte đầu ra  
    return F

# Các hàm nén cần dùng trong SHA512 theo bài báo rfc6234
def ROTR(x,n,w=64):                                                                 # Hàm quay vòng phải
    return ((x >> n) | ((x << (w - n)))) & 0xFFFFFFFFFFFFFFFF                

def CH(x,y,z):                                                                      # Conditional
    return (x & y) ^ ((~x) & z)
def MAJ(x,y,z):                                                                     # Majority
    return (x & y) ^ (x & z) ^ (y & z)
def BSIG0(x):
    return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39)
def BSIG1(x):   
    return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41)
def SSIG0(x):                                                                       # ROT Shift
    return ROTR(x,1) ^ ROTR(x,8) ^ ((x >> 7))
def SSIG1(x):
    return ROTR(x,19) ^ ROTR(x,61) ^ ((x >> 6))   


#----------------------------------------------------TOTP Function-----------------------------------------------------------#

def TOTP(K,tm,Digit = 6):                                                   # TOTP theo bài báo rfc6238
    HS = HMAC1(K,tm)                                                        # Lấy kết quả của thuật toán HMAC-SHA-512
    Sbits = DT(HS)                                                          # Cho qua hàm DT(Dynamic Trunk) để cắt bỏ xuống còn 4 bytes
    Snum = int(Sbits,base=16)                                               # Đổi từ dãy string Hex sang Interger
    D = str(Snum % (10**Digit))                                             # Giá trị sẽ rơi vào từ 0 -> 10**{Digit}-1
    D = '0'*(Digit-len(D)) + D                                              # Bổ sung 0 
    return D

def DT(HS):                                                                 # String = String[0]...String[63]
    offset ='0x' + HS[129:]                                                 # Lấy 4 bit cuối cùng của dãy và sẽ là offset
    offset = int(offset,base=16)
    if offset == 0:
        HS1 = HS[0:10]                                                      # Lấy 4 bytes
    else:
        HS1 = '0x' + HS[offset*2:offset*2+4*2]                              # Lấy 4 bytes tính từ chỉ sổ [offset]
    return HS1


#---------------------------------------------------Key initiation----------------------------------------------------------#

def getkey():                                                               # Lay secret key tren phan mem web
    file = open('WEB\web\static\key\skey.txt','r')
    k = file.read()
    file.close()
    return k


def Get_key():                                                              # Lấy hoặc tạo khóa 
    Key = secret.sharekey()  
    Key = bytes(Key,'ascii')                                                # Chuyển về byte
    Key = base64.b32decode(Key)                                             # Decode để lấy key
    Key = int(Key)                                                          # Chuyển về số nguyên
    # print(Key)
    start_time = time.time()                                                # Counter trong thuật toán TOTP là thời gian thực
    # counter = int(start_time/30)                                            # Cứ 30s thì counter tăng 1
    return Key

def reset_key():
    K = secret.reset_key()
    return K


def verify(secret,counter,id=0):
    D1,D2 = validate(secret,counter+id)
    return D1,D2



def counter_ini():                                                                      # khoi tao counter
    counter = int(time.time()/30)                                                    # Cứ 30s thì counter tăng 1  
                                                                                     # Theo bài báo TOTP kiểm chứng, 30s là thời gian cân bằng giữa việc xác thực và bảo mật                                                 
    return counter
    

#---------------------------------------------------Main function----------------------------------------------------------#

def validate(Key,counter):                                                                  # Validate  
    start_time = time.time()                                                        # Counter trong thuật toán TOTP là thời gian thực                                                                           
    Digit = int(input("Nhap so cac so OTP muon tao: "))                         # Để đảm bảo việc nhận thực thì OTP sẽ được kiểm tra tại timestamp hệ thống nhận được từ user
    D1 = TOTP(Key,counter,Digit)                                                # Do độ trễ của mạng thì quá trình kiểm tra rất có thể sẽ bị tính toán nhanh hơn 1 counter so với bên user
    D2 = TOTP(Key,counter-1,Digit)                                              # Để đảm bảo cho việc xác thực thì phải thêm cả trường hợp timestamp trước đó
                                                                                # Để tránh khỏi việc tấn công bởi Large window attack thì chỉ được giảm tối thiểu 1 counter
    end_time = time.time()                                
    print("Thời gian tổng: %.2f giây" % (end_time-start_time))
    print("Mã TOTP1: ",D1)
    print("Mã TOTP2: ",D2)
    counter = counter + 1
    return D1,D2

    
if __name__ == "__main__":                                                  # Gọi hàm main   
    counter = counter_ini()                                       
    # Key = Get_key()                                                         # Lấy hoặc tạo khóa
    Key = getkey()                                                              # Lay secret key tren web
    Key = int(base64.b32decode(Key))
    # print(Key)                                     
    validate(Key,counter)    
    A = input("Press Enter to Quit")   

#---------------------------------------------------END----------------------------------------------------------#