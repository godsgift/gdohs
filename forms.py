from flask_wtf import Form
from wtforms import TextField, PasswordField, validators, IntegerField, BooleanField, SelectField, SubmitField
from wtforms.validators import Required, Length, Email, ValidationError, Regexp, EqualTo, NumberRange
from wtforms.widgets import SubmitInput

class SignUp(Form):
	username = TextField("Username", validators=[Required("Please provide a username without any spaces"),
		Length(min=4, max=20), Regexp(r'^[\w.@+-]+$', message="Please provide a username without any spaces")])

	password = PasswordField("Password", validators=[Required("Please pick a secure password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces")])

	email = TextField("Email", validators=[Required("Please provide a valid email address"),
		Length(min=6, max=35), Email(message="That is not a valid email address"),
		Regexp(r'^[\w.@+-]+$', message="Please provide an email without any spaces")])

	firstname = TextField("First Name", validators=[Required("Please provide your first name"),
		Regexp(r'^[\w.@+-]+$', message="Please enter your first name without any spaces")])

	lastname = TextField("Last Name", validators=[Required("Please provide your last name"),
		Regexp(r'^[\w.@+-]+$', message="Please enter your last name without any spaces")])

class Login(Form):
	username = TextField("Username", validators=[Required("Please provide a username without any spaces"),
		Length(min=4, max=20), Regexp(r'^[\w.@+-]+$', message="Please provide a username without any spaces")])

	password = PasswordField("Password", validators=[Required("Please pick a secure password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces")])

class ForgotPassword(Form):
	email = TextField("Email", validators=[Required("Please provide a valid email address"),
		Length(min=6, max=35), Email(message="That is not a valid email address"),
		Regexp(r'^[\w.@+-]+$', message="Please provide an email without any spaces")])

class NewPassword(Form):
	password = PasswordField("Password", validators=[Required("Please pick a secure password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces")])

	confirm_password = PasswordField("Confirm Password", validators=[Required("Required"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces"),
		EqualTo("password", message="Passwords must match")])

class ChangePassword(Form):
	current_password = PasswordField("Current Password", validators=[Required("Please type in your current password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces")])

	password = PasswordField("New Password", validators=[Required("Please pick a secure password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces")])

	confirm_password = PasswordField("Confirm Password", validators=[Required("Required"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces"),
		EqualTo("password", message="Passwords must match")])

class CamSettings(Form):
	brightness = IntegerField("Brightness", default=50, validators=[Required("Please choose a number between 0 and 100"),
		NumberRange(min=0, max=100, message="Please choose a number between 0 and 100")])

	resolution = SelectField("Video/Image Resolution: ", choices=[("320x240", "320 x 240"), ("640x480", "640 x 480"), 
		("1280x1024", "1280 x 1024"), ("1920x1080", "1920 x 1080")], default="640x480", validators=[(Required("Required"))])

	hflip = BooleanField("Horizontal Flip: ", default=False)

	vflip = BooleanField("Vertical Flip: ", default=False)

class Recording(Form):
	start = SubmitField("Start Recording")

	stop = SubmitField("Stop Recording")

class LicensePlate(Form):
	license = TextField("License Plate", validators=[Required("Please provide a license plate without any spaces"),
		Length(min=4, max=10), Regexp(r'^[\w.@+-]+$', message="Please provide a license plate without any spaces")])
