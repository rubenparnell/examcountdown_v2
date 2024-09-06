from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, HiddenField, PasswordField, RadioField, BooleanField
from wtforms.validators import DataRequired 

#Create Sign Up form:
class SignUpForm(FlaskForm):
  username = StringField("Username", validators=[DataRequired()])
  email = StringField("Email", validators=[DataRequired()])
  password_hash = PasswordField("Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm Password", validators=[DataRequired()])
  privacyAgree = BooleanField("I agree to the Privacy Policy", validators=[DataRequired()])
  submit = SubmitField("Submit")

# Create Login Form:
class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class EmailForm(FlaskForm):
  email = StringField("Email", validators=[DataRequired()])
  submit = SubmitField("Submit")

class PwdResetForm(FlaskForm):
  password1 = PasswordField("Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField('Confirm')

class ConfirmPwdFrom(FlaskForm):
  form_type = HiddenField(default='confirm_pwd')
  password = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField('Confirm')

class UpdateForm(FlaskForm):
  form_type = HiddenField(default='update_profile')
  username = StringField('Username', validators=[DataRequired()])
  email = StringField('Email', validators=[DataRequired()])
  submit = SubmitField('Submit Changes')

class QualForm(FlaskForm):
  form_type = HiddenField(default='qual')
  Qualification = RadioField('Qualification', choices=[('2','GCSE'),('3a','AS Level'),('3b','A Level')])
