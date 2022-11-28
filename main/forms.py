from cProfile import label
from unicodedata import category
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,TextAreaField,IntegerField,SelectField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from main.extension import mongo
from flask_wtf.file import FileField, FileAllowed
import email_validator
from main.models import User,Post

category_choices= [
    ('electronics', 'electronics'),
    ('furnitures', 'furnitures'),
    ('bedding', 'bedding'),
    ('clothes', 'clothes'),
    ]


class LoginForm(FlaskForm):
    phonenumber = StringField('Phonenumber', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    phonenumber = StringField('Phonenumber', validators=[DataRequired()])
    first_name = StringField('First_name', validators=[DataRequired(), ])
    last_name = StringField('Last_name', validators=[DataRequired(), ])
   # image = FileField('Add Profile Pic', validators=[FileAllowed(['png','jpg','jpeg'])])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_phonenumber(self, phonenumber):
        user = User.query.filter_by(username=phonenumber.data).first()
        if user is not None:
            raise ValidationError('Please use a different phonenumber.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email.')

 #favorite_fruit= forms.CharField(label='What is your favorite fruit?', widget=forms.Select(choices=FRUIT_CHOICES))


class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    price = IntegerField('Price', validators=[DataRequired()])
    location = StringField('location', validators=[DataRequired()])
    category = SelectField('Category', choices = category_choices, validators = [DataRequired()])
    image1 = FileField('Add pictures',validators=[FileAllowed(['png','jpg','jpeg'])])
    image2 = FileField(validators=[FileAllowed(['png','jpg','jpeg'])])
    image3 = FileField(validators=[FileAllowed(['png','jpg','jpeg'])])
    submit = SubmitField('Submit')

class SellForm(FlaskForm):
    phonenumber = IntegerField('Phone Number', validators=[DataRequired()])
    price = SelectField(u'Amount', choices=[('200', '200'), ('100', '100') ])
    submit = SubmitField('Submit')

class RequestResetForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        
        user = User.query.filter_by(email=email.data)
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')