import hashlib
import os


from FlaskWeb import app
from datetime import datetime
from flask import Flask, render_template, flash, redirect, url_for, json
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, BooleanField, SubmitField
from flask_login import current_user, login_user, logout_user, UserMixin, LoginManager
from wtforms.validators import DataRequired

app.config['SECRET_KEY'] = 'fuck_flask_and_other_python_shit'

posts = []

username = "Name"
personalArea = "Sign In"
loginManager = LoginManager(app)


class User(UserMixin):
    KEY_LOGIN = 'login'
    KEY_PASSW = 'passw'

    userList = None

    login = ''
    passw = ''
    is_external = False

    def __init__(self, data):
        self.login = data[User.KEY_LOGIN]
        self.passw = data[User.KEY_PASSW]
           
    
    def avatar_url(self):
        try:
            return self.info['photo_50']
        except AttributeError:
            return ''

    def get_id(self):
        return self.login


    def check_password(self, password):
        return hashlib.md5(password.encode('utf-8')).hexdigest() == self.passw

    def __repr__(self):
        return F'User: {self.login}'

    def get_full_name(self):
        try:
            return self.info['first_name'] + ' ' + self.info['last_name']
        except AttributeError:
            return self.login


    @staticmethod
    @loginManager.user_loader
    def load_user(_login):
        if _login not in User.userList:
            return None
        else:
            return User.userList[_login]

    @staticmethod
    def load(_context):
        if not User.userList:
            filename = os.path.join(_context.root_path, 'data', 'userdata.json')
            file = open(filename, 'r')
            data = json.load(file)
            file.close()

            User.userList = {}
            for item in data:
                User.userList[item['login']] = User(item)

User.load(app)

@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    global personalArea
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    someUserName = current_user.login
    user = {'username': someUserName}
    somePosts = [
        {
            'author': {'username': 'Привет'},
            'body': 'Сообщение добавляется каждый раз при заходе на index'
        }
    ]
    return render_template('index.html',
        title=username,       
        personalText = someUserName,        
        year=datetime.now().year,
        logoutText = "Logout"
    )
@app.route('/contact')
def contact():
    """Renders the contact page."""    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template(
        'contact.html',
        title='Contact',
        year=datetime.now().year,
        personalText = current_user.login, 
        logoutText = "Logout",
        message='Some flask and python contacts.'
    )

@app.route('/about')
def about():
    """Renders the about page."""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template(
        'about.html',
        title='About',
        year=datetime.now().year,
        message='Enjoy the silence',
        logoutText = "Logout",
        personalText = current_user.login
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    global personalArea
    if current_user.is_authenticated:
        return redirect(url_for('userProfile'))
        # return redirect("/home")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.load_user(form.username.data)
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')            
            return redirect(url_for('login'))
        login_user(user)
        somePosts = [
            {
                'author': {'username': form.username.data},
                'body': form.password.data
            }
        ]        
        posts.extend(somePosts)
        return redirect("/home")
    return render_template('login.html',  title='Sign In', form=form)

@app.route('/userProfile', methods=['GET', 'POST'])
def userProfile():    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('userProfile.html',
                           title="Hello,"+ current_user.login,
                           message = "Whats Up? Nice log bro...",
                           personalText = current_user.login,
                           logoutText = "Logout"
                           )

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')
