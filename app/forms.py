from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from app import *


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(min=5, max=50)], render_kw={"placeholder": "Email Address"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Password"})

    def validate_username(self, username):
        existing_username = User.query.filter_by(
            username=username.data).first()
        if existing_username:
            raise ValidationError(
                'That username already exists, please choose a different one.')

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError(
                'That email already exists, please choose a different one.')


class CreateLinkForm(FlaskForm):
    link = StringField(validators=[InputRequired(), Length(
        min=5, max=200)], render_kw={"placeholder": "Link (Domain name only)"})
    link_name = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={
                            "placeholder": "Link Name (Name that will show up)"})


class AccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Edit Email"})
    bio = TextAreaField([Length(min=0, max=300)], render_kw={
        "placeholder": "Edit Bio"})

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError(
                    "That email address belongs to different user. Please choose a different one.")
