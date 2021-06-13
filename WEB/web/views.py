from flask import Blueprint, render_template,request,flash                                                # Là thiết kế cho ứng dụng: từng trang web (URL)
from flask_login import login_required, current_user
from . import db
from .models import Note




views = Blueprint('views',__name__)                                                          # Đặt cùng tên cho đơn giản

@views.route('/', methods = ['GET','POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note)<1:
            flash('Note qua ngan!',category = 'error')
        else:
            new_note = Note(data = note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note da duoc tao!', category = 'success')
    return render_template("home.html", user=current_user)

