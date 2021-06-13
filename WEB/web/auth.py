from flask import Blueprint, render_template, request, flash, redirect, sessions, url_for , session                            
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from time import time
from . import OTP1
from . import secret1
import base64

auth = Blueprint('auth',__name__)                                                                       # Đặt cùng tên cho đơn giản

@auth.route('/login/', methods=['GET', 'POST'])                                                         # Trang login
def login():
    if request.method == 'POST':
        email= request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()                                                # Truy cập vào database và tìm User theo email
        # user = User.select().where(User.email == resp.email).first()
        if user:
            if check_password_hash(user.password, password):                                            # Kiểm tra mật khẩu
                flash('Dang nhap lan thu nhat thanh cong!',category='success')        
                return redirect(url_for('auth.loginfa',email=email))                                    # Dẫn tới trang login lớp 2

            else:
                flash('Sai mat khau', category='error')
        else:
            flash('Sai email', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/loginfa/', methods=['GET', 'POST'])                                                       # Trang login lớp 2
def loginfa():
    user = current_user
    email = request.args['email']
    user = User.query.filter_by(email=email).first()
    file = open('WEB\web\static\key\skey.txt','r')
    skey = file.read()
    file.close()
    if request.method == 'POST':
        if user:
            code = request.form.get('code') 
            K = int(base64.b32decode(skey))
            t = int(time()/30)
            D1,D2 = OTP1.verify(K,t)
            file = open('WEB\web\static\key\digi.txt','r+')
            s = str(D1) + '-' + str(D2)
            file.write(s)
            file.close()
            if code == D1 or code == D2:
                login_user(user, remember=True)                                                         # Lưu trạng thái đăng nhập
                flash('Dang nhap thanh cong!',category='success')
                return redirect(url_for('views.home'))                                                  # Về trang home
            else:        
                flash('Thu lai!',category='error')
        else:
            return "<p> Opps </p>"
    return render_template("loginfa.html",sk = str(secret1.sharekey()), skey=skey, user=current_user)


@auth.route('/logout')                                                                                  # Logout ra trang login                                                                    
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))



@auth.route('/sign-up', methods=['GET', 'POST'])                                                        # Trang đăng ký
def sign_up():
    if request.method == 'POST':
        email= request.form.get('email')                                                                # Lấy email
        first_name = request.form.get('firstName')                                                      # Lấy tên
        password1 = request.form.get('password1')                                                       # Lấy password
        password2 = request.form.get('password2')                                                       # Lấy password2 để đảm bảo nhập password đúng theo mong muốn 
        user = User.query.filter_by(email=email).first()                                                # Truy cập vào database và tìm User theo email

        if user:
            flash('Email da ton tai. Chon email khac',category='error')
        elif len(email) < 4:
            flash('Email phai lon hon 4 ki tu.',category='error')
        elif len(first_name) < 2:
            flash('Ten phai lon hon 1 ki tu.',category='error')
        elif password1 != password2:
            flash('Mat khau phai giong nhau.',category='error')
        elif len(password1) < 7:
            flash('Mat khau phai dai it nhat 7 ki tu.',category='error')
        else:
            secret1.reset_key()
            k = str(OTP1.Get_key())                                                                                                                 # Tạo secret key cho user
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'), otp_secret = k )       # tao user
            db.session.add(new_user)                                                    # them vao database
            db.session.commit()                                                         # thong bao update database

            flash('Tai khoan da duoc tao',category='success')
            # login_user(user, remember=True)                                             # Luu trang thai dang nhap
            return redirect(url_for('views.home'))                                                                                                  # Về trang home
    return render_template("sign_up.html", user=current_user)
    
