from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from forms import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '574d6ae483e049f1b2575c8a455c6e0e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profile_picture = db.Column(
        db.String(20), nullable=False, default='default.jpg')
    links = db.relationship('Link', backref='owner', lazy='dynamic')


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String(100), nullable=False)
    link_name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=["GET", "POST"])
def home():
    return render_template('pages/home.html', title='Home')


@app.route('/dashboard', methods=['GET', "POST"])
@login_required
def dashboard():
    links = Link.query.filter_by(owner=current_user).all()
    links_total = 0
    for link in links:
        links_total += 1
    return render_template('pages/dashboard.html', title='Dashboard', links=links, links_total=links_total)


@app.route('/create-link', methods=['GET', 'POST'])
@login_required
def create_link():
    form = CreateLinkForm()
    if form.validate_on_submit():
        new_link = Link(link=form.link.data,
                        link_name=form.link_name.data, owner=current_user)
        db.session.add(new_link)
        db.session.commit()
        flash('Your link has successfully been created! You can view your site from the navbar above.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('forms/create_link.html', title='Create Link', form=form)


@app.route('/<username>')
def view_site(username):
    user = User.query.filter_by(username=username).first_or_404()
    links = Link.query.all()
    return render_template('pages/site.html', title=user.username, user=user, links=links)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
            flash("Incorrect password.", 'warning')
        if user is None:
            flash("This account does not exist.", 'warning')

    return render_template('forms/login.html', title="Login", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data)
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('forms/register.html', title="Register", form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
