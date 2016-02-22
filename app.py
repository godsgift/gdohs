import re
from flask import *
from flask.ext.pymongo import PyMongo
# from flask.ext.security import Security
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import TextField, PasswordField, validators
from wtforms.validators import Required, Length, Email, ValidationError, Regexp

app = Flask(__name__)

#Mongodb Settings
app.config['MONGO_DBNAME'] = 'gdohs'
#need to add username and pass for db

#WTFORMS Settings
app.secret_key= 'testing'

#Enable extensions for flask
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

#Running db:
#mongod --dbpath data


@app.route("/")
def index():
	#Redirect to home page
	return render_template("index.html")

@app.route("/showSignup")
def showSignup():
	form = SignUp()
	#Redirect to the sign up page with the form
	return render_template("signup.html", form=form)

@app.route("/signUp", methods=['GET', 'POST'])
def signUp():
	if (request.method == 'POST'):
		form = SignUp(request.form)

		if form.validate_on_submit():
			_username = form.username.data
			_password = form.password.data
			_email = form.email.data
			_firstname = form.firstname.data
			_lastname = form.lastname.data

			print _username + _password + _email + _firstname + _lastname
			#check if username exists in database
			
			print "Username VALIDATED"
		else:
			print"USERNAME FAILED"
			return render_template('signup.html', form=form)
	return render_template('signup.html', form=SignUp())

# @app.route("/signUp", methods=['POST', 'GET'])
# def signUp():
# 	#Grab user input
# 	_username = request.form['username']
# 	_password = request.form['password']
# 	_email = request.form['email']
# 	_firstname = request.form['firstname']
# 	_lastname = request.form['lastname']

# 	#If all user inputs have no whitespaces, proceed with sign up
# 	if (checkWhitespace(_username) and checkWhitespace(_password) and checkWhitespace(_email) and
# 		checkWhitespace(_firstname) and checkWhitespace(_lastname)):
# 		#If username already exists in database, send to sign up failure page
# 		if (mongo.db.user.find_one({"username": _username})):
# 			return render_template("signupfail.html", code=307)
# 		else:
# 			#Encrypt the password
# 			pw_hash = bcrypt.generate_password_hash(_password)
# 			#Add the new user into the database
# 			result = mongo.db.user.insert_one(
# 				{
# 					"username": _username,
# 					"password": pw_hash,
# 					"email": _email,
# 					"firstname": _firstname,
# 					"lastname": _lastname
# 				}
# 			)
# 		#Send to sign up success page if user was able to complete the sign up
# 		return render_template("signupsuccess.html", code=307)
# 	else:
# 		return render_template("index.html")

@app.route("/showForgotPassword")
def showForgotPassword():
	#Redirect to the forgot password page
	return render_template("forgotpassword.html")

@app.route("/checkUser", methods=['POST'])
def checkUser():
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
		Regexp(r'^[\w.@+-]+$')])

	lastname = TextField("Last Name", validators=[Required("Please provide your last name"),
		Regexp(r'^[\w.@+-]+$')])


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


if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')