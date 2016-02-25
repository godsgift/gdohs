import re
from config import *
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from random import randint
from flask import *
from flask.ext.pymongo import PyMongo
from flask_mail import Mail, Message
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import TextField, PasswordField, validators
from wtforms.validators import Required, Length, Email, ValidationError, Regexp, EqualTo

##########################################################################
#
#								 GLOBAL
#
##########################################################################

app = Flask(__name__)

#Mongodb Settings
app.config['MONGO_DBNAME'] = DB_Name
#need to add username and pass for db
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = Mail_User
app.config['MAIL_PASSWORD'] = Mail_Pass
#WTFORMS Settings
app.secret_key = SECRET_KEY

#Enable extensions for flask
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

rand_num = randint(0,20000)


#Running db:
#mongod --dbpath data

##########################################################################
#
#								LOGGED OUT
#
##########################################################################

@app.route("/")
def index():
	form = Login()
	#Redirect to home page
	return render_template("index.html", form=form)

@app.route("/showSignup")
def showSignup():
	form = SignUp()
	#Redirect to the sign up page with the form
	return render_template("signup.html", form=form)

@app.route("/signUp", methods=['GET', 'POST'])
def signUp():
	if (request.method == 'POST'):
		#Grab the data from user input
		form = SignUp(request.form)
		#If the form has been validated
		if form.validate_on_submit():
			#Grab data from each field
			_username = form.username.data
			_password = form.password.data
			_email = form.email.data
			_firstname = form.firstname.data
			_lastname = form.lastname.data

			#If all user inputs have no whitespaces, proceed with sign up
			if (checkWhitespace(_username) and checkWhitespace(_password) and checkWhitespace(_email) and
				checkWhitespace(_firstname) and checkWhitespace(_lastname)):
				#If username already exists, send an error to the page
				if (mongo.db.user.find_one({"username": _username})):
					form.username.errors.append("Username already taken")
					return render_template('signup.html', form=form)
				elif (mongo.db.user.find_one({"email": _email})):
					form.email.errors.append("Email already taken")
				else:
					#Encrypt the password
					pw_hash = bcrypt.generate_password_hash(_password)
					#Add the new user into the database
					result = mongo.db.user.insert_one(
						{
							"username": _username,
							"password": pw_hash,
							"email": _email,
							"firstname": _firstname,
							"lastname": _lastname
						}
					)
				#Send to sign up success page if user was able to complete the sign up
				return render_template("signupsuccess.html")
			else:
				return render_template('signup.html', form=form)
		else:
			return render_template('signup.html', form=form)
	return render_template('signup.html', form=SignUp())

@app.route("/showForgotPassword")
def showForgotPassword():
	form = ForgotPassword()
	#Redirect to the forgot password page
	return render_template("forgotpassword.html", form=form)

@app.route("/forgotPassword", methods=['GET', 'POST'])
def forgotPassword():
	if (request.method == 'POST'):
		#create token
		form = ForgotPassword(request.form)

		if form.validate_on_submit():
			#get the email data that the user input
			_email = form.email.data
			#Check if email exists
			checkEmail = mongo.db.user.find_one({"email": _email})
			if (checkEmail):
				#Get required data based from the email
				get_email = checkEmail["email"]
				get_id = checkEmail["_id"]
				get_fname = checkEmail["firstname"]
				get_lname = checkEmail["lastname"]

				get_num = rand_num
				#Create a token using the id of the user
				token = get_token(get_num)
				#get the server IP and port
				server = request.host

				reset_pass_email(get_fname, get_lname)
				#Add onto the database (reestpassword collection connected to the user)

				#Send email with the link to their reset password to the user



		return render_template("/forgotpassword.html", form=form)


@app.route("/showResetPassword")
def showResetPassword():
	form = NewPassword()
	return render_template("newpassword.html", form=form)

@app.route("/resetPassword/<token>")
def resetPassword(token):
	#if the decrypted token matches the one with the database, show the form
		#get the user_id from database and find the same id in user collection

		#if validate on submit
			#
	form = NewPassword()
	return render_template("newpassword.html", form=form)

@app.route("/login")
def login():
	return


##########################################################################
#
#								CLASSES
#
##########################################################################

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

	confirm_password = PasswordField("Confirm Password", validators=[Required("Please type a password"),
		Regexp(r'^[\w.@+-]+$', message="Please provide a password without any spaces"),
		EqualTo("password", message="Passwords must match")])

##########################################################################
#
#							HELPER FUNCTIONS
#
##########################################################################

def checkWhitespace(word):
	#Checks for all types of whitespaces including \t, \n, \f, \v
	ws = re.search('[\s+]', word)
	#True for no whitespace
	checker = True

	#If there is whitespace then set checker to false
	if (ws):
		checker = False

	return checker

def get_token(self, expiration=1800):
	s = Serializer(app.secret_key, expiration)
	serializedToken = s.dumps(self)
	return serializedToken

def reset_pass_email(firstname, lastname):
	msg = Message("Hello " + firstname + lastname,sender="stevenharperfan1@gmail.com", recipients=["stevenharperfan1@gmail.com"])
	msg.body = "This is the email body"
	mail.send(msg)
	return

if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')