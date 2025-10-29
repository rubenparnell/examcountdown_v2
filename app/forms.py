from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, ValidationError, HiddenField, BooleanField, SelectField, SelectMultipleField, EmailField, TimeField, RadioField
from wtforms.validators import DataRequired, Email
from flask_wtf.file import FileField, FileAllowed

class LoginForm(FlaskForm):
  email = EmailField("Email", validators=[DataRequired()])
  password = PasswordField("Password", validators=[DataRequired()])
  rememberMe = BooleanField("Remember Me")
  submit = SubmitField("Continue")

class SignUpForm(FlaskForm):
  username = StringField("Username", validators=[DataRequired()])
  email = EmailField("Email", validators=[DataRequired(), Email()])
  password1 = PasswordField("Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField("Continue")

  def validate_username(self, username):
    if "@" in username.data:
      raise ValidationError("Usernames cannot contain '@' symbol. Please choose a different username.")
    if " " in username.data:
      raise ValidationError("Usernames cannot contain spaces. Please choose a different username.")

class MigrationForm(FlaskForm):
  password1 = PasswordField("Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField("Continue")

class UpdateForm(FlaskForm):
  form_type = HiddenField(default='update_profile')
  username = StringField('Username', validators=[DataRequired()])
  profile_picture = FileField(
    "Profile Picture",
    validators=[FileAllowed(['jpg', 'jpeg', 'png'], "Images only!")]
  )

  submit = SubmitField('Submit Changes')

  def validate_username(self, username):
    if "@" in username.data:
      raise ValidationError("Usernames cannot contain '@' symbol. Please choose a different username.")
    if " " in username.data:
      raise ValidationError("Usernames cannot contain spaces. Please choose a different username.")

class OldPwdResetForm(FlaskForm):
  form_type = HiddenField(default='password_reset')
  oldPassword = PasswordField("Old Password", validators=[DataRequired()])
  password1 = PasswordField("New Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm New Password", validators=[DataRequired()])
  submit = SubmitField('Confirm')

class ConfirmPwdForm(FlaskForm):
  form_type = HiddenField(default='confirm_pwd')
  password = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField('Confirm')

class EmailForm(FlaskForm):
  email = StringField("Email", validators=[DataRequired()])
  submit = SubmitField("Submit")

class PwdResetForm(FlaskForm):
  password1 = PasswordField("Password", validators=[DataRequired()])
  password2 = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField('Confirm')


class QualForm(FlaskForm):
  form_type = HiddenField(default='qual')
  Qualification = RadioField('Qualification', choices=[('GCSE','GCSE'),('AS','AS Level'),('A','A Level')])

class TimeForm(FlaskForm):
  form_type = HiddenField(default='exam_times')
  AM_time = TimeField('AM Exams')
  PM_time = TimeField('PM Exams')
  submit = SubmitField('Confirm')