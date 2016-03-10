from flask_wtf import Form
from wtforms import TextField, PasswordField, validators, IntegerField, BooleanField, SelectField
from wtforms.validators import Required, Length, Email, ValidationError, Regexp, EqualTo, NumberRange

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

	resolution = SelectField("Video/Image Resolution: ", choices=[(1, "320 x 240"), (2, "640 x 480"), (3, "1920 x 1080")],
	 default=2, validators=[(Required("Required"))])

	video_time = SelectField("Video Timing: ", choices=[(1, "1 Hour"), (2, "5 Hours"), (3, "10 Hours"), (4, "16 Hours"), (5, "24 Hours")], 
		default=3, validators=[Required("Required")])

	video_num = SelectField("Video Number: ", choices=[(8, 8),(9, 9),(10, 10),(11, 11),(12, 12),(13, 13),(14, 14),(15, 15),
		(16, 16), (17, 17), (18, 18), (19, 19),(20, 20)], default=10, validators=[Required("Required")])

	hflip = BooleanField("Horizontal Flip: ", default=False, validators=[Required("Required")])

	vflip = BooleanField("Vertical Flip: ", default=False, validators=[Required("Required")])
