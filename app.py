from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('This username has already been taken. Please choose another one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField("Login")

class CommentForm(FlaskForm):
    comment = StringField('Comment', validators=[InputRequired()])
    submit = SubmitField("Comment")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

FORBIDDEN_WORDS = ['bullshit', 'shit', 'dumb', 'damn', 'stupid', 'idiot']
comments = []

def filter_text(text):
    text_lower = text.lower()
    for word in FORBIDDEN_WORDS:
        text_lower = text_lower.replace(word, '*' * len(word))
    return text_lower

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('comment'))
        flash('Login failed. Check your username and/or password.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/comment', methods=['GET', 'POST'])
@login_required
def comment():
    form = CommentForm()
    response = ""
    
    # Handle comment submission
    if form.validate_on_submit():
        comment = form.comment.data
        filtered_comment = filter_text(comment)
        if any(word in comment.lower() for word in FORBIDDEN_WORDS):
            flash('Your comment contains forbidden words. Please avoid posting foul language.')
        else:
            comments.append({'username': current_user.username, 'comment': filtered_comment})
            flash('Comment added successfully!', 'success')
    
    # Handle mood selection
    mood = request.args.get('mood')
    if mood in answers:
        if not request.cookies.get(mood):
            index = index_tracker[mood]
            response = answers[mood][index]
            index_tracker[mood] = (index + 1) % len(answers[mood])
            expire_date = datetime.datetime.now() + datetime.timedelta(days=1)
            resp = make_response(render_template('comment.html', form=form, comments=comments, response=response))
            resp.set_cookie(mood, 'done', expires=expire_date)
            return resp
        else:
            response = "You have already answered this question today."
    
    return render_template('comment.html', form=form, comments=comments, response=response)

@app.route('/delete/<int:comment_id>')
@login_required
def delete(comment_id):
    comment = next((comment for comment in comments if comment['username'] == current_user.username and comments.index(comment) == comment_id), None)
    if comment:
        comments.remove(comment)
        flash('Comment deleted successfully!', 'success')
    else:
        flash('You do not have permission to delete this comment.', 'danger')
    return redirect(url_for('comment'))

answers = {
    'q1': [
        "That's wonderful! It's the little moments of joy that make life beautiful.",
        "Great to hear! Keep enjoying those good vibes!",
        "Awesome! Sounds like you had a fantastic time!"
    ],
    'q2': [
        "An okay day is still a step forward. Keep looking for those little good moments.",
        "Sometimes neutral is just what we need. Keep going!",
        "Not every day can be exciting, but that's okay!"
    ],
    'q3': [
        "I'm sorry to hear that. Remember, tough times don't last forever.",
        "Bad days happen, but better days are ahead.",
        "Hang in there, tomorrow is a new start!"
    ]
}

index_tracker = {'q1': 0, 'q2': 0, 'q3': 0}

@app.route('/how_was_your_day', methods=['GET', 'POST'])
@login_required
def how_was_your_day():
    response = ""
    if request.method == 'POST':
        question = request.form.get('question')
        if question in answers:
            if not request.cookies.get(question):
                index = index_tracker[question]
                response = answers[question][index]
                index_tracker[question] = (index + 1) % len(answers[question])

                resp = make_response(render_template('comment.html', response=response))
                expire_date = datetime.datetime.now() + datetime.timedelta(days=1)
                resp.set_cookie(question, 'done', expires=expire_date)
                return resp
            else:
                response = "You have already answered this question today."
    return render_template('comment.html', response=response)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Log out is successful. Hope to see you soon')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
