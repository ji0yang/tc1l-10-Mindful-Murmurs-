from flask import Flask, render_template, request, redirect, url_for, flash, make_response
# database
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from flask_bcrypt import Bcrypt
from flask_wtf.file import FileField, FileAllowed
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

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
    # allow user to post picture but only in jpg,jpeg and png
    image = FileField('Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    video = FileField('Video', validators=[FileAllowed(['mp4', 'mov'], 'Videos only!')])

    submit = SubmitField("Comment")

class ResetPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# not allow user to comment these word
FORBIDDEN_WORDS = ['bullshit', 'shit', 'dumb', 'damn', 'stupid', 'idiot']
comments = []

def filter_text(text):
    text_lower = text.lower()
    for word in FORBIDDEN_WORDS:
        text_lower = text_lower.replace(word, '*' * len(word))
    return text_lower


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        print("Form data:", form.data)  
        user = User.query.filter_by(username=form.username.data).first()
        print("User found:", user)  
        if user:
            if form.new_password.data == form.confirm_password.data:
                hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                flash('Password reset successfully! Please log in with your new password.')
                return redirect(url_for('login'))
            else:
                flash('New password and confirm password do not match.')
        else:
            flash('Username not found.')
    return render_template('reset_password.html', form=form)

# make user log in then direct it to home page
@app.route('/')
@login_required
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# log in details
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            # after log in direct user to home page
            return redirect(url_for('home'))
        flash('Login failed. Check your username and/or password.')
    return render_template('login.html', form=form)

# register details
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        # direct user to log in page after register
        flash('Account created! You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

def allowed_file(filename):
    allowed_extensions = {'jpg', 'jpeg', 'png', 'mp4'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png','mp4',}

@app.route('/comment', methods=['GET', 'POST'])
@login_required
def comment():
    form = CommentForm()
    response = ""

    if form.validate_on_submit():
        comment = form.comment.data
        filtered_comment = filter_text(comment)

        if any(word in comment.lower() for word in FORBIDDEN_WORDS):
            flash('Your comment contains foul language. Please try again')
        else:
            image_filename = None
            video_filename = None

            if 'image' in request.files:
                image_file = request.files['image']
                if image_file and allowed_file(image_file.filename):
                    image_filename = secure_filename(image_file.filename)
                    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

            if 'video' in request.files:
                video_file = request.files['video']
                if video_file and allowed_file(video_file.filename):
                    video_filename = secure_filename(video_file.filename)
                    video_file.save(os.path.join(app.config['UPLOAD_FOLDER'], video_filename))

            comments.append({
                'id': len(comments),
                'username': current_user.username,
                'comment': filtered_comment,
                'image': image_filename,
                'video': video_filename,
                'timestamp': datetime.now().strftime('%y-%m_%d %H:%M:%S'),
                'likes': 0
            })
            flash('Comment added!')

    mood = request.args.get('mood')
    if mood in answers:
        if not request.cookies.get(mood):
            index = index_tracker[mood]
            response = answers[mood][index]
            index_tracker[mood] = (index + 1) % len(answers[mood])
            expire_date = datetime.now() + timedelta(days=1)
            resp = make_response(render_template('comment.html', form=form, comments=comments, response=response))
            resp.set_cookie(mood, 'done', expires=expire_date)
            return resp
        else:
            response = "You have already answered this question today."

    return render_template('comment.html', form=form, comments=comments, response=response)


@app.route('/like/<int:comment_id>')
@login_required
def like_comment(comment_id):
    comment_to_like = next((c for c in comments if c['id'] == comment_id), None)
    if comment_to_like:
        if current_user.username not in comment_to_like.get('liked_by', []):
            comment_to_like['likes'] += 1
            comment_to_like.setdefault('liked_by', []).append(current_user.username)
            flash('You liked the comment!', 'success')
        else:
            flash('You have already liked this comment.', 'info')
    else:
        flash('Comment not found.', 'danger')
    return redirect(url_for('comment'))

# delete comment
@app.route('/delete/<int:comment_id>')
@login_required
def delete(comment_id):
    global comments
    # check user before deleting its comment
    comment_to_delete = next((c for c in comments if c['id'] == comment_id and c['username'] == current_user.username), None)
    if comment_to_delete:
      
        comments = [c for c in comments if not (c['id'] == comment_id and c['username'] == current_user.username)]
        flash('Comment deleted successfully!', 'success')
    else:
        flash('You do not have permission to delete this comment.', 'danger')
    return redirect(url_for('comment'))

answers = {
    'q1': [
        "That's wonderful! It's the little moments of joy that make life beautiful.",
        "Great to hear! Keep enjoying those good vibes!",
        "Awesome! Sounds like you had a fantastic time!",
        "I love looking in the mirror and feeling good about what I see!",
        "It sounds like you had an absolutely amazing day, and I'm so glad to hear that!",
        "I'm really happy to hear that your day went so well. It must have been quite enjoyable!",
        "It's fantastic to know that your day turned out so great. You deserve it!",
        "It's so heartwarming to hear that your day was so enjoyable. I hope it was filled with great moments!",
        "It's great to hear that today was such a good day for you. I hope the positive energy carries through to tomorrow!",
        "Your day sounds wonderful, and I'm thrilled that you had such a good experience today."

    ],
    'q2': [
        "An okay day is still a step forward. Keep looking for those little good moments.",
        "Sometimes neutral is just what we need. Keep going!",
        "Not every day can be exciting, but that's okay!",
        "Glad to hear your day was okay. Sometimes a day that's just average can be surprisingly pleasant.",
        "Sometimes an okay day is just what we need to reset and prepare for better things ahead. Glad it was decent!",
        "An okay day is better than a bad one. I'm happy to hear you had a relatively uneventful but decent day.",
        "Sounds like it was a pretty average day for you. Sometimes those days are just what we need for a bit of normalcy.",
        "I'm glad it was an okay day. Sometimes those days are necessary to keep things balanced and steady.",
        "Even though it was just an okay day, it's good to hear it wasn't too stressful. Here's to hoping for something better soon!",
        "It sounds like today was a normal day. Even those can be important and have their own little moments of satisfaction."
    ],
    'q3': [
        "I'm sorry to hear that. Remember, tough times don't last forever.",
        "Bad days happen, but better days are ahead.",
        "Hang in there, tomorrow is a new start!",
        "Bad days are tough, and I'm sorry you had to experience one today. I hope things get better soon.",
        "I'm sorry your day was rough. Everyone has those kinds of days, and I hope tomorrow is much better for you.",
        "It's unfortunate that you had a rough day. I'm here if you need support or just someone to listen.",
        "I'm sorry you had a hard day. Remember that every difficult day is followed by new opportunities for better moments.",
        "Bad days can be really tough to get through, and I'm sorry you had to experience one today. I hope tomorrow is kinder.",
        "I'm sorry today didn't go well for you. It's important to remember that tough days are just part of life's ups and downs.",
        "I'm really sorry to hear that you had a hard day. Hang in there; sometimes it's the difficult days that make us stronger."
    ]
}

index_tracker = {'q1': 0, 'q2': 0, 'q3': 0}


# let user to choose their mood after commeting 
# only allow user to choose once per day
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

@app.route('/calendar')
@login_required
def calendar():
    today = datetime.today().day
    return render_template('calendar.html', today=today)

# Log out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Log out is successful. Hope to see you soon')
    return redirect(url_for('login'))

if __name__ == '__main__':
# create a folder call uploads automatically if it wasnt created manually
    if not os.path.exists('static/uploads'):
        os.makedirs('static/uploads')
#make the new tables run correctly 
    with app.app_context():
        db.create_all()

    app.run(debug=True)