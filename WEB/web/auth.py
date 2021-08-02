from flask import Blueprint, render_template, request, flash, redirect, sessions, url_for , session                            # Là thiết kế cho ứng dụng: từng trang web (URL)
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from time import time
from . import OTP1
from . import secret1
import base64

auth = Blueprint('auth',__name__)                                           # Đặt cùng tên cho đơn giản

def gen_pass_hash(pas):
    p = OTP1.SHA512(pas)
    return p

def check_pass(user_pass,pas):
    p = OTP1.SHA512(pas)
    if user_pass == p:
        return True
    else:
        return False

@auth.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email= request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        # user = User.select().where(User.email == resp.email).first()
        if user:
            if check_pass(user.password, password):    
                flash('Dang nhap lan thu nhat thanh cong!',category='success')        
                return redirect(url_for('auth.loginfa',email=email))

            else:
                flash('Sai mat khau', category='error')
        else:
            flash('Sai email', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/loginfa/', methods=['GET', 'POST'])
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
                login_user(user, remember=True)                             # Luu trang thai dang nhap
                flash('Dang nhap thanh cong!',category='success')
                # login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:        
                flash('Thu lai!',category='error')
        else:
            return "<p> Opps </p>"
    return render_template("loginfa.html",sk = str(secret1.sharekey()), skey=skey, user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email= request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()

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
            k = str(OTP1.Get_key())
            new_user = User(email=email, first_name=first_name, password=gen_pass_hash(password1), otp_secret = k )      # tao user
            db.session.add(new_user)                                                    # them vao database
            db.session.commit()                                                         # thong bao update database

            flash('Tai khoan da duoc tao',category='success')
            # login_user(user, remember=True)                                             # Luu trang thai dang nhap
            return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)
    
