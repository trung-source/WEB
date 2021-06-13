from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from .secret1 import reset_key
from .OTP1 import Get_key


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default = func.now())        # func la mot ham lay date o trong SQLalchemy
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))               # tao khoa phu



class User(db.Model, UserMixin):                                              # Khoi tao model
    id = db.Column(db.Integer, primary_key = True)                            # primary key: phan biet cac truong, khong bi trung lap
    email = db.Column(db.String(150), unique=True)                            # email ko the bi trung va max = 150
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    otp_secret = db.Column(db.String(1000))
    notes = db.relationship('Note')                                         # Lien ket user va note: one-many


    # def __init__(self, **kwargs):
    #     super(User, self).__init__(**kwargs)
    #     if self.otp_secret is None:
    #         reset_key()
    #         self.otp_secret = str(Get_key())










