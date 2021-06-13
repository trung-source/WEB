
#-------------------------------------RSA CSPRNG ALGORITHM-------------------------------------------#
import time


def gcd(a, b):
    while b != 0:
        a, b = b, a % b                                       # Dựa theo tính chất gcd(a,b)=gcd(b,r)
    return a


def multiplicative_inverse(b, a):                               # Nghịch đảo nhân của b trong tập a
    t0 = 0
    t1 = 1
    d = a                                                       # Lưu lại giá trị 
    while b > 0:
        q = a // b
        r = a % b
        t = t0 - t1*q
        a,b = b,r
        t0,t1=t1,t
    if a == 1:                                                  # Xác định giá trị nghịch đảo nhân
        if t0 > 0:
            return t0
        if t0 < 0:
            return t0 + d

def prime(x):                                                   # Kiểm tra có phải số nguyên tố
    for i in range(2,x):
        if x % i == 0:
            return False
        else:
            return True

def genkey(p,q):                                                # Tạo khóa
    if not (prime(p) and prime(q)):
        raise Exception("q hoặc p không phải nguyên tố.")
    if p == q:
        raise Exception("p and q không được bằng nhau.")
    else:
        n = p * q
        phi = (p-1) * (q-1)
        seed = int(time.time())
        x = seed % n
        e = []
        for i in range(2,phi):
            if gcd(phi,i) == 1:
                e.append(i)
        indx = seed % len(e)
        e = e[indx]
        # print(e)

        z ='0b'
        l = seed % 1024                                                 
        while(l < 512):
            l = (l + seed) % n
        # print(l)                                                       # l sẽ có chiều dài từ 512 -> 1024                          
        for i in range(0,l):
            x1 = pow(x,e,n)                                             # x1 = x^e mod n
            x = x1
            z += bin(x1)[-1]                                            # Lấy bin cuối
        # print(z)
    return z                



def main():                                                             # Gọi hàm main
    q = int(input("Nhập số nguyên tố q: "))
    p = int(input("Nhập số nguyên tố p: "))
    # p , q = []
    a = genkey(p,q)
    print(len(a))
    print(int(a,base=2))

if __name__ == "__main__":                                                  # Gọi hàm main  
    start_time = time.time()                                        
    main()  
    end_time = time.time()
    print("%.2f seconds" % (end_time-start_time))
    A = input("Press Enter to Quit")   


#-------------------------------------------END--------------------------------------------------#