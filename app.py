##########################################################################
# SOURCE FILE:	app.py
#
# AUTHOR: 		ELTON SIA
#
# PROGRAM:		Web application for the automatic garage door opener and 
#				home surveillance (GDOHS). 
#
# DATE:			April 07, 2016
#
# USAGE:		Ensure that the values in the config file have been
#				changed. The license plate reading server (lprserver.py)
#				is up and running. The mongodb instance is running as 
#				well.
#			
#				sudo python app.py
#
##########################################################################

##########################################################################
#
#								 IMPORTS
#
##########################################################################

import re
import picamera
import time
import os
import io
import picamera.array
import requests
import numpy as np
from threading import Lock, Thread
from sense_hat import SenseHat
from picamera.exc import *
from forms import *
from config import *
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from random import randint
from flask import *
from flask.ext.pymongo import PyMongo
from flask_mail import Mail, Message
from flask.ext.bcrypt import Bcrypt
from flask.ext.login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user


##########################################################################
#
#								 GLOBAL
#
##########################################################################

app = Flask(__name__)

#Mongodb Settings from config file
app.config['MONGO_DBNAME'] = DB_Name
app.config['MONGO_USERNAME'] = DB_User
app.config['MONGO_PASSWORD'] = DB_Pass

#Flask-Mail Settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
#User and password taken from config file
app.config['MAIL_USERNAME'] = Mail_User
app.config['MAIL_PASSWORD'] = Mail_Pass

app.secret_key = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(app)

#Enable extensions for flask
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

#Global Variables
rand_num = randint(0,200000)
camera = None
cameralock = Lock()
stop_record = None
user_email = None
gd_open = None
flock = False

##########################################################################
#
#							LOGGED OUT FUNCTIONS
#
##########################################################################

##########################################################################
# Function Name: index()
#
# Parameters: None
#
# Posted Data: None
#
# Return Values:
#	HTTP - Web page with a login form
#
# Description:
#	Sends the user to the login page with an empty login form.
#
##########################################################################
@app.route("/")
def index():
	#Redirect to home page
	form = Login()
	return render_template("index.html", form=form)

##########################################################################
# Function Name: login()
#
# Parameters: None
#
# Posted Data:
#	username
#	password
#
# Return Values:
#	HTTP - Web page for logged in home page.
#
#	HTTP - Web page for incorrect username or password
#	     - Redirects to index() function
#
# Description:
#	Takes the username and password entered by the user and is checked in
#	the database for a match. If the correct username and password was 
#	given, then the user gets logged in the web application. However,
#	if the username or the password given is incorrect, they are 
#	redirected to the index() home page with an error message.
#
##########################################################################
@app.route("/login", methods=["GET", "POST"])
def login():
	if (request.method == 'POST'):
		form = Login(request.form)
		if(form.validate_on_submit()):
			#user input
			_username = form.username.data
			_password = form.password.data

			#check if user exist in db
			user = mongo.db.user.find_one({"username": _username})
			if (user):
				#Grab required data
				user_id = user["_id"]
				user_name = user["username"]
				user_pass = user["password"]

				#If user gives the correct password, then log them in
				if (User.validate_login(user_pass, _password)):
					user_obj = User(user_id, user_name, user_pass)
					login_user(user_obj)
					next = request.args.get('next')
					return redirect(next or url_for("home"))
				else:
					flash("Incorrect username or password.")
					return render_template("index.html", form=form)
			else:
				flash("Incorrect username or password.")
				return render_template("index.html", form=form)
		else:
			flash("Incorrect username or password.")
			return render_template("index.html", form=form)
	else:
		flash("Incorrect username or password.")
		return render_template("index.html", form=form)
	return render_template("index.html", form=form)

##########################################################################
# Function Name: showSignup()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Web page with empty sign-up form
#
# Description:
#	Sends the user to the sign up web page with an empty form.
#
##########################################################################
@app.route("/showSignup")
def showSignup():
	form = SignUp()
	#Redirect to the sign up page with the form
	return render_template("signup.html", form=form)

##########################################################################
# Function Name: signUp()
#
# Parameters: None
#
# Posted Data:
#	_username
#	_password
#	_email
#	_firstname
#	_lastname
#
# Return Value:
#	HTTP - sends user to the sign-up successful page
#	HTTP - sends user back to the sign-up page with some form data 
#		   completed
#
# Description:
#	Takes the username, password, email, firstname, and lastname data
#	entered by the user and do submission validation, whitespace
#	validation, unique username validation, and unique email validation.
#	When the data passes all the validation, then they will be added to
#	the database. If it fails any of the validation, they will be
#	redirected back to the sign-up page with the correct error message.
#	The password is hashed and salted to ensure that it will be harder
#	to crack.
#
##########################################################################
@app.route("/signUp", methods=['GET', 'POST'])
def signUp():
	if (request.method == 'POST'):
		#Grab the data from user input
		form = SignUp(request.form)
		#If the form has been validated
		if (form.validate_on_submit()):
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
					flash("Email already taken")
					return render_template('signup.html', form=form)
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
							"lastname": _lastname,
							"forcelock": False
						}
					)
				#Send to sign up success page if user was able to complete the sign up
				return render_template("signupsuccess.html")
			else:
				return render_template('signup.html', form=form)
		else:
			return render_template('signup.html', form=form)
	return render_template('signup.html', form=SignUp())

##########################################################################
# Function Name: showForgotPassword()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - renders the web page for forgot password page
#
# Description:
#	Renders the show forgot password page for the user with an empty form.
#
##########################################################################
@app.route("/showForgotPassword")
def showForgotPassword():
	form = ForgotPassword()
	#Redirect to the forgot password page
	return render_template("forgotpassword.html", form=form)

##########################################################################
# Function Name: forgotPassword()
#
# Parameters: None
#
# Posted Data:
#	_email
#
# Return Value:
#	HTTP - Sends the user back to the forgot password page.
#
# Description:
#	Takes the email entered by the user and do submission validation. if
#	the validation passes, Checks if password exist, if it does gets the 
#	id, firstname and lastname for the user with that email. Then creates
#	a token and creates a link with that token for the user. Then checks
#	if the user already requested a previous forgot password link and 
#	deletes it if it exist in the database. Once it has been deleted,
#	adds the user into the database and sends an email to the user with 
#	the link to the reset password page. If the user puts in incorrect
#	email (which means that the email does not exist in the database),
#	a message appears that the email was sent to the specified email.
#	This is to ensure that people won't know which emails exist in the
#	database and which email do not exist.
#
##########################################################################
@app.route("/forgotPassword", methods=['GET', 'POST'])
def forgotPassword():
	if (request.method == 'POST'):
		form = ForgotPassword(request.form)
		if (form.validate_on_submit()):
			#get the email data that the user input
			_email = form.email.data
			if (checkWhitespace(_email)):
				#Check if email exists
				checkEmail = mongo.db.user.find_one({"email": _email})
				if (checkEmail):
					#Get required data based from the email
					get_email = checkEmail["email"]
					get_user_id = checkEmail["_id"]
					get_fname = checkEmail["firstname"]
					get_lname = checkEmail["lastname"]
					#get the server IP and port
					server = request.host
					get_num = rand_num
					#Create a token using a random number
					token = get_token(get_num)
					link = server + "/showResetPassword/" + token
					if mongo.db.resetpassword.find_one({"user_id": get_user_id}):
						mongo.db.resetpassword.delete_one({"user_id": get_user_id})
						#Add onto a temporary document in the database
						result = mongo.db.resetpassword.insert_one(
							{
								"user_id": get_user_id,
								"email": get_email,
								"random_number": get_num
							}
						)
						flash("Password reset link has been sent to " + _email)
						#Send email with the link to their reset password to the user
						reset_pass_email(get_email, get_fname, get_lname, link)
					else:
						#Add onto a temporary document in the database
						result = mongo.db.resetpassword.insert_one(
							{
								"user_id": get_user_id,
								"email": get_email,
								"random_number": get_num
							}
						)
						flash("Password reset link has been sent to " + _email)
						#Send email with the link to their reset password to the user
						reset_pass_email(get_email, get_fname, get_lname, link)
				else:
					flash("Password reset link has been sent to " + _email)
					return render_template("/forgotpassword.html", form=ForgotPassword())
			else:
				return render_template("/forgotpassword.html", form=form)
		else:
			return render_template("/forgotpassword.html", form=form)
	return render_template("/forgotpassword.html", form=ForgotPassword())

##########################################################################
# Function Name: showResetPassword()
#
# Parameters: token
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders message page with error message
#	HTTP - Renders reset password page.
#
# Description:
#	First checks if the token in the URL is correct(verifies it by 
#	decrypting). If the verified token is "Signature Expired", send
#	to the error message page with that error. If the verified token is
#	"Bad Signature", send the user to the error message page with that 
#	error. If the verified token is correct and is has not expired,
#	checks the database if the decrypted token matches with any document.
#	If it matches with a document, get the user_id and based on that
#	user_id get the username. Add the username into a session to be used
#	later on when the user clicks the reset password button. Flashes a 
#	message to the user to allow them to change their password.
#
##########################################################################
@app.route("/showResetPassword/<token>")
def showResetPassword(token):
	verified_token = verify_token(token)
	form = NewPassword()
	if (verified_token == "Signature Expired"):
		#Send to an error page
		flash("Signature Token Expired")
		return render_template("messages.html")
	elif (verified_token == "Bad Signature"):
		#Send to an error page
		flash("Bad Token Signature")
		return render_template("messages.html")
	else:
		#Find the user_id with the same token
		temp_user = mongo.db.resetpassword.find_one({"random_number": verified_token})
		if (temp_user):
			#Find the user with the correct ID
			user_id = temp_user["user_id"]
			user = mongo.db.user.find_one({"_id": user_id})
			data = str(user["username"])
			#Add the user into a session
			session["username_rpass"] = data
			flash("Hello " + data + ". Please enter your new password.")
			return render_template("newpassword.html", form=form)
		return render_template("newpassword.html", form=form)
	return render_template("newpassword.html", form=form)

##########################################################################
# Function Name: resetPassword()
#
# Parameters: None
#
# Posted Data:
#	password
#	confirmpassword
#
# Return Value:
#	HTTP - Renders to success change password page
#	HTTP - Renders to the reset password page
#
# Description:
#	First grabs the user from the session, and grab the user_id based
#	of the username. Takes the password and confirm password entered by
#	the user and do submission validation as well as makign sure
#	that the password and the confirm password fields matches with each
#	other. If it matches, hash and salt that password and set the users
#	password to the new password. Destroy the username session after the
#	password has been changed and delete the user from the reset password
#	database. After a success reset password, the user is sent to the 
#	success reset password page. If there are any errors from the 
#	validation, the user gets sent back to the reset password page. 
#
##########################################################################
@app.route("/resetPassword", methods=['GET', 'POST'])
def resetPassword():
	#Grab the user from session
	_user = session["username_rpass"]
	#Find the user ID that requested the reset password
	find_user = mongo.db.user.find_one({"username": _user})
	user_id = find_user["_id"]
	if (request.method == 'POST'):
		form = NewPassword(request.form)
		if (form.validate_on_submit()):
			#Grab the data from the fields
			_password = form.password.data
			_confirm_password = form.confirm_password.data
			#If the passwords match, begin updating the database for the user
			if (_password == _confirm_password):
				#Hash the password
				pw_hash = bcrypt.generate_password_hash(_password)
				#Update database for user from the session
				mongo.db.user.update_one({"_id": user_id}, {"$set": {"password": pw_hash}})
				#Delete the user from the session
				session.pop("username_rpass", None)
				#Delete user from temporary database
				mongo.db.resetpassword.delete_one({"user_id": user_id})
				flash("You have successfully reset your password.")
				return render_template("messages.html")

			flash("Hello " + _user + ". Please enter your new password")
			return render_template("newpassword.html", form=form)
		else:
			flash("Hello " + _user + ". Please enter your new password")
			return render_template("newpassword.html", form=form)
		flash("Hello " + _user + ". Please enter your new password")
	return render_template("newpassword.html", form=form)

##########################################################################
# Function Name: unauthorized_handler():
#
# Parameters: None
#
# Posted Data: None
#	
# Return Value:
#	HTTP - Renders the unauthorized page.
#
# Description:
#	This page is only rendered when the user tries to access a page that
#	requires someone to be logged in.
#
##########################################################################
@login_manager.unauthorized_handler
def unauthorized_handler():
	flash("Must be logged in to view this page.")
	return render_template("messages.html")

##########################################################################
#
#							LOGGED IN FUNCTIONS
#
##########################################################################

##########################################################################
# Function Name: home()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the logged in home page
#
# Description:
#	Renders the home page for users that are logged in.
#
##########################################################################
@app.route("/home")
@login_required
def home():
	return render_template("home.html")

##########################################################################
# Function Name: livestream()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the live stream page
#
# Description:
#	Renders the live stream page for the user
#
##########################################################################
@app.route("/livestream")
@login_required
def livestream():
	return render_template("live-stream.html")

##########################################################################
# Function Name: videostream()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	The video feed from the camera
#
# Description:
#	Grab the current logged in user and get their camera settings.
#	If they have a specified camera settings, use that settings when the
#	camera starts up. If not, use a default settings specified.
#
##########################################################################
@app.route("/videostream")
@login_required
def videostream():
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_id = find_user["_id"]
	#get camera settings set by that user from the database
	check_user = mongo.db.settings.find_one({"user_id": user_id})
	#Use default Settings
	if (check_user is None):
		brightness = 50
		hflip = False
		vflip = False
		return Response(generate_frames(Camera(), brightness, hflip, vflip),
	                    mimetype='multipart/x-mixed-replace; boundary=frame')
	else:
		brightness = check_user["brightness"]
		hflip = check_user["hflip"]
		vflip = check_user["vflip"]
		return Response(generate_frames(Camera(), brightness, hflip, vflip),
	                    mimetype='multipart/x-mixed-replace; boundary=frame')

##########################################################################
# Function Name: showDownloadVideos()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the download page for the user with the videos from the
#	raspberry pi system.
#
# Description:
#	Grabs the list of videos that are currently in the videos folder.
#	Note that these are the recorded videos by the user. If videos exist,
#	show it to the user. If there are no videos, then flash a message
#	that to let the user know that there are no videos in the folder.
#
##########################################################################
@app.route("/showDownloadvideos")
@login_required
def showDownloadVideos():
	videos = os.listdir("videos")
	num_vid = len(videos)
	if not videos:
		flash("There are currently no videos that can be downloaded")
		return render_template("video.html", count=num_vid)
	else:
		return render_template("video.html", videos=videos, count=num_vid)
	return render_template("video.html", videos=videos, count=num_vid)

##########################################################################
# Function Name: downloadvideos()
#
# Parameters: filename
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the download videos page
#
# Description:
#	When the user clicks the download videos link, the user is presented
#	to download that video. Once they have finished downloading the 
#	video, they are redirected to the download videos page.
#
##########################################################################
@app.route("/downloadvideos/<filename>")
@login_required
def downloadvideos(filename):
	videos = os.listdir("videos")
	for video in videos:
		if (filename == video):
			return send_from_directory('videos', video, as_attachment=True)
	return redirect(url_for("showDownloadVideos"))

##########################################################################
# Function Name: deletevideos()
#
# Parameters: filename
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the download video page
#
# Description:
#	When the user clicks the delete videos link, the video gets deleted 
#	from the folder. Once the user clicks the videos, the user gets 
#	redirected to the download videos page.
#
##########################################################################
@app.route("/deletevideos/<filename>")
@login_required
def deletevideos(filename):
	folder = "videos"
	videos = os.listdir(folder)
	for video in videos:
		if (video == filename):
			os.remove(folder+"/"+filename)
	return redirect(url_for("showDownloadVideos"))

##########################################################################
# Function Name: showSettings()
#
# Parameters: None
#
# Posted Data: None
#	
# Return Value:
#	HTTP - Renders the settings page
#
# Description:
#	Renders the settings page of the user. First checks the database if 
#	the user has a camera settings specified. If they do, get it and 
#	shows those settings for the user when the page is rendered. If not, 
#	then just show the settings page without the user settings.
#
##########################################################################
@app.route("/showSettings")
@login_required
def showSettings():
	form = CamSettings()
	#Find current user
	username = current_user.username
	user_id = username_to_userid(username)
	#check if user had set a settings previously
	check_user = mongo.db.settings.find_one({"user_id": user_id})
	#Show the user the current settings to the HTML
	if (check_user):
		brightness = check_user["brightness"]
		resolution = check_user["resolution"]
		hflip = check_user["hflip"]
		vflip = check_user["vflip"]
		return render_template("settings.html", form=form, 
			brightness=brightness, resolution=resolution, hflip=hflip, vflip=vflip)
	else:
		return render_template("settings.html", form=form)
	return render_template("settings.html", form=form)

##########################################################################
# Function Name: settings()
#
# Parameters: None
#
# Posted Data:
#	_brightness
#	_resolution
#	_horizontal flip
#	_vertical flip
#
# Return Value:
#	HTTP - Renders the settings page
#
# Description:
#	Takes the brightness, resolution, hflip, and vflip entered by the 
#	user and do submission validation as well as back-end checks for each
#	field in the form. If the validations are successful, first get the
#	current logged in user and get their user_id. Check the settings
#	collection from the database and check if said user exist. If user
#	does not exist, then insert the settings that the user had just
#	specified. If the user already exists in the setting collection, then
#	update the current settings to the new settings specified by the user.
#	If the validations are unsuccessful, then redirect the user to the 
#	settings page with the appropriate error message.
#
##########################################################################
@app.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():
	if (request.method == 'POST'):
		form = CamSettings(request.form)
		if (form.validate_on_submit()):
			#grab the data from the form
			_brightness = form.brightness.data
			_resolution = form.resolution.data
			_hflip = form.hflip.data
			_vflip = form.vflip.data
			#check for each field in form
			if (_brightness >= 0 and _brightness <= 100):
				if (_resolution == "320x240" or _resolution == "640x480" or _resolution == "800x600"):
					if (_hflip == True or _hflip == False):
						if (_vflip == True or _vflip == False):
							#Find the current logged in user
							username =  current_user.username
							#Get the user id based off of the current logged in user
							user_id = username_to_userid(username)
							check_user = mongo.db.settings.find_one({"user_id": user_id})
							#If the user does not exist in the collection then add it
							if (check_user is None):
								#Add  user specified settings to the settings collection
								result = mongo.db.settings.insert_one(
									{
										"user_id": user_id,
										"brightness": _brightness,
										"resolution": _resolution,
										"hflip": _hflip,
										"vflip": _vflip
									}
								)
								flash("Settings Updated")
							#If user does exist, update the fields to the new values
							elif (check_user is not None):
								mongo.db.settings.update(
									{"user_id": user_id}, 
									{"$set": 
										{
											"brightness": _brightness,
											"resolution": _resolution,
											"hflip": _hflip,
											"vflip": _vflip
										}
									}
								)
								flash("Settings Updated")
						else:
							#Vertical flip error check
							form.vflip.errors.append("Choice not valid")
							return render_template("settings.html", form=form)
					else:
						#Horizontal flip error check
						form.hflip.errors.append("Choice not valid")
						return render_template("settings.html", form=form)
				else:
					#Resolution error check
					form.resolution.errors.append("Choice not valid")
					return render_template("settings.html", form=form)
			else:
				#Brightness error check
				form.brightness.errors.append("Brightness must be between 0 and 100")
				return render_template("settings.html", form=form)
		else:
			#if form fails to validate
			return render_template("settings.html", form=form)
	else:
		return redirect(url_for("showSettings"))
	return redirect(url_for("showSettings"))

##########################################################################
# Function Name: showProfile()
#
# Parameters: None
#
# Posted Data: None
#	
# Return Value:
#	HTTP - Render the profile page with the license plate form, force
#			lock form, and the garage form.
#
# Description:
#	Get the current logged in user and get their firstname, lastname,
#	email, and their force lock settings. Show the 3 forms and the user
#	information when the page is rendered.
#
##########################################################################
@app.route("/showProfile")
@login_required
def showProfile():
	#Show user data in profile page
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_fname = find_user["firstname"]
	user_lname = find_user["lastname"]
	user_email = find_user["email"]
	user_flock = find_user["forcelock"]
	#Forms to be shown in the profile page
	form = LicensePlate()
	forceform = ForceLock()
	garageform = GarageDoor()
	return render_template("profile.html", form=form, forceform=forceform, 
		fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)

##########################################################################
# Function Name: addLicense()
#
# Parameters: None
#
# Posted Data:
#	license
#
# Return Value:
#	HTTP - Renders the profile page with the 3 forms
#
# Description:
#	First grab the current logged in user so that when the add license
#	button is clicked, it will render the page with the correct 
#	information. On top of that, we get the 2 other forms that are 
#	included in the profile page. Once the user enters their license
#	plate, we do submission validation on the data entered. If the
#	validation passes, we then do a whitespace validation. If all 
#	validation passes, we first check if the user already has an existing
#	license plate, and if they do, we update it and set it to the new
#	license plate. We first hash and salt the license plate as well before
#	updating or inserting the license plate. If the user does not have a
#	license plate in the database, we insert a new license plate for the
#	user. If it was successful, a message pops up saying that the license
#	plate has been updated. Otherwise, an appropriate error message pops 
#	up.
#
##########################################################################
@app.route("/addLicense", methods=['GET', 'POST'])
@login_required
def addLicense():
	#User data to be shown in the profile page
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_fname = find_user["firstname"]
	user_lname = find_user["lastname"]
	user_email = find_user["email"]
	user_flock = find_user["forcelock"]

	#Other forms in the page
	forceform = ForceLock()
	garageform = GarageDoor()

	if (request.method == "POST"):
		form=LicensePlate(request.form)
		if (form.validate_on_submit()):
			license = form.license.data
			#Check for whitespaces
			if (checkWhitespace(license)):
				#Grab userid
				user_id = username_to_userid(username)
				#if user exist in license collection, update it
				check_user = mongo.db.license.find_one({"user_id": user_id})
				if (check_user):
					#Hash the license
					license_hash = bcrypt.generate_password_hash(license)

					#Update the new license plate at the end
					mongo.db.license.update_one({"user_id": user_id}, {"$set": {'license': license_hash}})
					flash("License plate updated")
				else:
					#Add the first license plate into the license document
					license_hash = bcrypt.generate_password_hash(license)
					result = mongo.db.license.insert_one(
						{
							"user_id": user_id,
							"license": license_hash
						}
					)
					flash("License plate added")
			else:
				flash("License plate must not have any whitespaces")
				return render_template("profile.html", form=form, forceform=forceform, 
					fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)
		else:
			return render_template("profile.html", form=form, forceform=forceform, 
				fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)
	else:
		return redirect(url_for("showProfile"))
	return redirect(url_for("showProfile"))

##########################################################################
# Function Name: forcelock()
#
# Parameters: None
#
# Posted Data:
#	flock [True, False]
#
# Return Value:
#	HTTP - Renders profile page with all 3 forms.
#
# Description:
#	First grab the current logged in users to show the information
#	in the profile page. The 2 other forms are also included to be rendered
#	in the profile page. We also have a global "flock" that is needed to
#	change the force lock between True and False. When the user clicks the
#	button, it checks if the force lock is True or False. If the force lock
#	is True, then change it to False, for global use, and then update the
#	force lock in the database to False as well. If the force lock is
#	False, then change it to True, for global use, and then update the
#	force lock in the database to True as well. Whenever they click the
#	force lock button, they are rendered back to the profile page with the
#	user information as well as the correct force lock settings.
#
##########################################################################
@app.route("/forcelock", methods=['GET', 'POST'])
@login_required
def forcelock():
	global flock
	#User data in the page
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_fname = find_user["firstname"]
	user_lname = find_user["lastname"]
	user_email = find_user["email"]
	user_flock = find_user["forcelock"]

	#Other forms in the page
	form=LicensePlate()
	garageform = GarageDoor()

	if (request.method == "POST"):
		forceform = ForceLock(request.form)
		if (forceform.validate_on_submit()):
			data = forceform.forcelock.data
			if (data is True):
				#Change forcelock from true to false and vice versa
				if (user_flock is True):
					#Set force lock into false
					flock = False
					#Change force lock to false
					mongo.db.user.update_one({"username": username}, {"$set": {'forcelock': False}})
				elif (user_flock is False):
					#Set force lock into true
					flock = True
					#Change force lock to True
					mongo.db.user.update_one({"username": username}, {"$set": {'forcelock': True}})
				else:
					print "Error"
					return render_template("profile.html", form=form, forceform=forceform, 
						fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)
			else:
				return render_template("profile.html", form=form, forceform=forceform, 
					fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)
		else:
			return render_template("profile.html", form=form, forceform=forceform, 
				fname=user_fname, lname=user_lname, email=user_email, flock=user_flock, garageform=garageform)
	return redirect(url_for("showProfile"))

##########################################################################
# Function Name: mgdopen()
#
# Parameters: None
#
# Posted Data:
#	gd_open [True, False]
#
# Return Value:
#	HTTP - Renders the profile page with the 3 forms
#
# Description:
#	Grabs the current logged in user and get the required information
#	to be displayed in the profile page as well as the 2 other forms
#	that are required to be displayed in the profile page. When the user
#	clicks the button, the gd_open is changed to True, and ensures that
#	even if the force lock is True or False, it turns on the LED lights.
#	After the LED lights are done running, changes the gd_open to None and
#	renders the profile page again. If the gd_open was already True, sends
#	a message to the user to let them know that the LED lights are 
#	currently running. Otherwise just render the profile page with the
#	correct information.
#
##########################################################################
@app.route("/manual", methods=['GET', 'POST'])
@login_required
def mgdopen():
	global gd_open
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_fname = find_user["firstname"]
	user_lname = find_user["lastname"]
	user_email = find_user["email"]
	user_flock = find_user["forcelock"]

	#Other forms in the page
	form=LicensePlate()
	garageform = GarageDoor()
	forceform = ForceLock()

	if (request.method == "POST"):
		garageform = GarageDoor(request.form)
		if (garageform.validate_on_submit()):
			data = garageform.opengarage.data
			#Checks if the button was clicked
			if (data is True):
				#Checks if LED is currently on before proceeding
				if (gd_open is None):
					gd_open = True
					if (flock is True or flock is False):
						gd_sense()
						gd_open = None
					else:
						return redirect(url_for("showProfile"))
				elif(gd_open is True):
					flash ("LED lights are currently on")
					return redirect(url_for("showProfile"))
			else:
				redirect(url_for("showProfile"))
		else:
			redirect(url_for("showProfile"))
	return redirect(url_for("showProfile"))

##########################################################################
# Function Name: showChangePassword
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Render the change password page
#
# Description:
#	Renders the change password page with the change password form.
#
##########################################################################
@app.route("/showChangePassword")
@login_required
def showChangePassword():
	form = ChangePassword()
	return render_template("changepassword.html", form=form)

##########################################################################
# Function Name: changePassword()
#
# Parameters: None
#
# Posted Data:
#	current_password
#	new_password
#	match_password
#
# Return Value:
#	HTTP - Renders the change password page
#
# Description:
#	Takes the current_password, new_password, and match_password entered
#	by the user and do submission validation, check whitespace validation,
#	current password matching validation, and the new password matching
#	validation. When all the validation passes, the users password is 
#	updated to the new password. Otherwise, they are sent back to the
#	change password page.
#
##########################################################################
@app.route("/changePassword", methods=['GET', 'POST'])
@login_required
def changePassword():
	if (request.method == 'POST'):
		form = ChangePassword(request.form)
		current_password = form.current_password.data
		new_password = form.password.data
		match_password = form.confirm_password.data
		#Validates form and checks for whitespaces
		if (form.validate_on_submit() and checkWhitespace(current_password) and checkWhitespace(new_password)
			 and checkWhitespace(match_password)):
			#Check if current password matches in database
			username = current_user.username
			find_user = mongo.db.user.find_one({"username":username})
			check_password = bcrypt.check_password_hash(find_user["password"],current_password)
			if (check_password):
				#Check if the 2 password fields matches
				if (new_password == match_password):
					#Hash the new password
					new_hash_pass = bcrypt.generate_password_hash(new_password)
					#Update to the new password
					mongo.db.user.update_one({"username": username}, {"$set": {'password': new_hash_pass}})
					flash("Password Updated")
				else:
					form.confirm_password.errors.append("Password must match with new password")
					return render_template("changepassword.html", form=form)
			else:
				form.current_password.errors.append("Current password is incorrect")
				return render_template("changepassword.html", form=form)
		else:
			return render_template("changepassword.html", form=form)
	return render_template("changepassword.html", form=form)

##########################################################################
# Function Name: showRecordvideos()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the record videos page
#
# Description:
#	Renders the record videos page with the recodring form.
#
##########################################################################
@app.route("/showRecordvideos")
@login_required
def showRecordvideos():
	form = Recording()
	return render_template("recordvideos.html", form=form)

##########################################################################
# Function Name: startrecord()
#
# Parameters: None
#
# Posted Data:
#	start
#	stop
#
# Return Value:
#	HTTP - Renders the record videos page
#
# Description:
#	If the user clicks the start recording button, a submission validation
#	is done to ensure that the start button is clicked. If the camera is
#	currently in use, send a message to the web page saying it us
#	currently in use. If camera is not in use, grab the username of the
#	current logged in user and get their camera settigns from the database.
#	If they have no camera settings specified, set the global camera as
#	the picamera. and start recording with the default settings. If they
#	have camera settings specified, set the global camera as the picamera
#	and start recording with the camera settings. The global user_email
#	is set when the user_id was gotten so that it could be used later.
#	Once the recording has started, flash a message to the web page
#	stating when the recording started.
#
##########################################################################
@app.route("/startrecord", methods=['GET', 'POST'])
@login_required
def startrecord():
	form = Recording()
	global camera
	global user_email
	if (request.method == 'POST'):
		form = Recording(request.form)
		#grab user input
		start = form.start.data
		stop = form.stop.data
		#User wants to start recording
		if (start == True and stop == False):
			try:
				with cameralock:
					#get user id of the logged in user
					username = current_user.username
					find_user = mongo.db.user.find_one({"username": username})
					user_id = find_user["_id"]
					#Get user email to send the images when motion is detected
					user_email = find_user["email"]
					#get camera settings set by that user from the database
					check_user = mongo.db.settings.find_one({"user_id": user_id})
					if (check_user is None):
						#Start camera with default settings
						camera = picamera.PiCamera()
						camera.resolution = (640,480)
						time.sleep(2)
						#create filename
						filename = create_savefile("video")
						camera.start_recording(filename, motion_output=MyMotionDetector(camera))
						flash("Started recording on " + time.strftime("%Y-%m-%d %I:%M:%S") + " with default settings.")
					else:
						#Grab user settings
						brightness = check_user["brightness"]
						hflip = check_user["hflip"]
						vflip = check_user["vflip"]
						unicode_resolution = check_user["resolution"]
						#Change from unicode to int and get width and height from string
						int_resolution = string_split_res(unicode_resolution)
						width = int_resolution[0]
						height = int_resolution[1]
						#Use the settings set by the user
						camera = picamera.PiCamera()
						camera.resolution = (width,height)
						camera.brightness = brightness
						camera.hflip = hflip
						camera.vflip = vflip
						time.sleep(2)
						#create filename
						filename = create_savefile("video")
						camera.start_recording(filename, motion_output=MyMotionDetector(camera))
						flash("Started recording on " + time.strftime("%Y-%m-%d %I:%M:%S") + " with users' camera settings.")
						return render_template("recordvideos.html", form=form)
			except (PiCameraMMALError, PiCameraError, PiCameraAlreadyRecording):
				flash("Camera already in use. Please ensure that there is no one in the livestream page or stop the recording")
		else:
			flash("Error, please refresh the page and try again")
			return render_template("recordvideos.html", form=form)
	return render_template("recordvideos.html", form=form)

##########################################################################
# Function Name: stoprecord()
#
# Parameters: None
#
# Posted Data:
#	start
#	stop
#
# Return Value:
#	HTTP - Renders the record video page
#
# Description:
#	If the user clicks the stop recording button, do a submission
#	validation ensuring that the stop button was clicked. Set the global
#	stop_record to True. Checks if the global camera is None, and if it
#	is, flash a message stating that the camera is not in use. If camera
#	is not None, record for 20 seconds more then stop recoding and close
#	the camera instance. Flash a message stating that the camera had
#	stopped recording and show the current time. Set the global camera and
#	global user_email to None. If there are any errors, print them. Then
#	calls the delete_images() function and deletes all the images in the
#	motion-images folder. Once all of the above are done, renders the 
#	record videos page with the appropriate messages.
#
##########################################################################
@app.route("/stoprecord", methods=['GET', 'POST'])
@login_required
def stoprecord():
	global camera
	global stop_record
	global user_email
	form = Recording()
	if (request.method == 'POST'):
		form = Recording(request.form)
		#grab user input
		start = form.start.data
		stop = form.stop.data
		if (stop == True and start == False):
			#Set stop recording to true so that 
			#the motion detector can stop taking pictures
			stop_record = True
			if (camera is None):
				flash("Camera is not recording. Please start recording before stopping it.")
			else:
				try:
					with cameralock:
						camera.wait_recording(20)
						camera.stop_recording()
						camera.close()
						flash("Stopped Recording on " + time.strftime("%Y-%m-%d %I:%M:%S") + ".")
						#set to none so that it can be used again later on
						camera = None
						user_email = None
				except (PiCameraMMALError, PiCameraError, PiCameraAlreadyRecording, 
					PiCameraRuntimeError, PiCameraNotRecording) as e:
					print e
				#Deletes all the images in the motion-images directory
				delete_images()
		else:
			flash ("Error, please try again")
			return render_template("recordvideos.html", form=form)
	return render_template("recordvideos.html", form=form)

##########################################################################
# Function Name: logout()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	HTTP - Renders the home page for logged out users
#
# Description:
#	When the user clicks the logout button, they are logged out from the 
#	web application and are then redirected to the home page for logged
#	out users.
#
##########################################################################
@app.route("/logout")
@login_required
def logout():
	logout_user()
	form = Login()
	return render_template("index.html", form=form)

##########################################################################
#
#								CLASSES
#
##########################################################################

##########################################################################
# Class Name: User()
#
# Function Names: __init__()
#				  is_active()
#				  is_authenticated()
#				  is_anonymous()
#				  get_id()
#				  validate_login()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value:
#	Depending on the function called inside the class, will return
#	the appropriate return message.
#
# Description:
#	The User class is used in tandem with the login and logout function
#	This is part of the flask-login library and is required for using it.
#	The functions inside are required before using the flask-login
#	library.
#
##########################################################################
class User():

	##########################################################################
	# Function Name: __init__()
	#
	# Parameters: self, id, username, password
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Sets the id, username, and password for the class.
	#
	##########################################################################
	def __init__(self, id, username, password):
		self.id = id
		self.username = username
		self.password = password

	##########################################################################
	# Function Name: is_active()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value:
	#	True
	#
	# Description:
	#	Sets the the active to True if a user is logged in.
	#
	##########################################################################
	def is_active(self):
		return True

	##########################################################################
	# Function Name: is_authenticated()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value:
	#	True
	#
	# Description:
	#	Sets the authenticated to True if the user has been authenticated.	
	#
	##########################################################################
	def is_authenticated(self):
		return True

	##########################################################################
	# Function Name: is_anonymous()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value:
	#	False
	#
	# Description:
	#	Sets the anonimity to False. Note that this is always false because
	#	the web application does not allow anonymous users.
	#
	##########################################################################
	def is_anonymous(self):
		return False

	##########################################################################
	# Function Name: get_id()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value:
	#	username
	#
	# Description:
	#	Returns the username which will be added into the Flask session.
	#
	##########################################################################
	def get_id(self):
		return self.username

	##########################################################################
	# Function Name: validate_login()
	#
	# Parameters: pw_hash, password
	#
	# Posted Data: None
	#
	# Return Value:
	#	Boolean - True/False
	#
	# Description:
	#	Check the if the hashed and salted password matches for when the user
	#	logs in. If it matches return True, if it doesn't return False.
	#
	##########################################################################
	@staticmethod
	def validate_login(pw_hash, password):
		return bcrypt.check_password_hash(pw_hash, password)

##########################################################################
# Class Name: MyMotionDetector
#
# Function Names: analyse()
#				  email_image()
#				  send_email()
#	 			  send_lpr()
#				  send_request
#				  agdopen
#
# Parameters: picamera.array.PiMotionAnalysis
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	The camera motion detector class which was included in the picamera
#	library.
#
##########################################################################
class MyMotionDetector(picamera.array.PiMotionAnalysis):

	##########################################################################
	# Function Name: analyse()
	#
	# Parameters: self, a
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Uses the numpy array to check if there are any changes in the 
	#	3 dimensional array of motion vectors from the H.264 video encoder.
	#	If there are more than 10 vectors with a magnitude greater than 60,
	#	a motion has been detected. Once motion has been detected, if the
	#	global stop_record is None, start a timer and capture 5 images with
	#	different names in a 5 second time frame. Once the 5 images are saved,
	#	call the email_image function with the 5 images and the global 
	#	user_email to send it to the user and call the send_lpr function to 
	#	send the 5 images to the license plate reading server. End the timer 
	#	and print the timer. Wait 3 more seconds before going back 
	#	to analyse mode. If the global stop_record is True, sleep for 20
	#	seconds and set the stop_record to None.
	#
	##########################################################################
	def analyse(self, a):
		global stop_record
		global user_email
		
		a = np.sqrt(
		    np.square(a['x'].astype(np.float)) +
		    np.square(a['y'].astype(np.float))
		    ).clip(0, 255).astype(np.uint8)
	    # If there're more than 10 vectors with a magnitude greater
	    # than 60, motion has been detected
		if ((a > 60).sum() > 50):
			#if the stop recording button has not been clicked yet,
			#start taking pictures with the camera and send to
			#the license plate reading server and email to client
			if (stop_record is None):
				start = time.time()
				filenames=[]
				try:
				    #Take 5 pictures with different filenames (5 seconds)
					for i in range(5):
						filename = create_savefile("image")
						#Add the filenames to the list
						filenames.append(filename)
						camera.capture(filename, use_video_port=True)
						time.sleep(1)
				except (PiCameraRuntimeError, PiCameraError, PiCameraMMALError) as e:
					print e
					return

				#Send pictures via email
				self.email_image(user_email, filenames[0],filenames[1],filenames[2], filenames[3],filenames[4])
				#Send images to the license plate reading server
				self.send_lpr(LPR_Server, filenames[0],filenames[1],filenames[2],
						filenames[3],filenames[4])

				# time.sleep(5)
				end = time.time()
				print (end-start)
				time.sleep(3)

			elif (stop_record is True):
				time.sleep(20)
				stop_record = None
		return

	##########################################################################
	# Function Name: email_image()
	#
	# Parameters: self, remail, filename1, filename2, filename3, filename4,
	#			  filename5
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Sets the subject, body, sender, and the recipients of the email.
	#	Attaches the 5 imaged that is passed from the global user_email.
	#	Create a thread with the arguments [app, msg] and targets the 
	#	send_email() function. Starts the thread.
	#
	##########################################################################
	def email_image(self, remail, filename1, filename2, filename3, filename4, filename5):
		subject = "Motion Detected"
		body = "Attached are 5 images that were taken when your camera had detected a motion"
		
		msg = Message(subject=subject, body=body,
			sender=Mail_User,
			recipients=[remail])

		#Attach the 5 images to the email and send them to the user
		with app.open_resource(filename1) as fp:
		    msg.attach(filename1, "image/jpeg", fp.read())
		with app.open_resource(filename2) as fp:
		    msg.attach(filename2, "image/jpeg", fp.read())
		with app.open_resource(filename3) as fp:
		    msg.attach(filename3, "image/jpeg", fp.read())
		with app.open_resource(filename4) as fp:
		    msg.attach(filename4, "image/jpeg", fp.read())
		with app.open_resource(filename5) as fp:
		    msg.attach(filename5, "image/jpeg", fp.read())

		thr = Thread(target=self.send_email, args=[app, msg])
		thr.start()
		return

	##########################################################################
	# Function Name: send_email()
	#
	# Parameters: self, app, msg
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Sets the flask's app context to inside the thread and sends the email
	#	with the "msg" that was created in the email_image() function.
	#
	##########################################################################
	def send_email(self, app, msg):
		with app.app_context():
			mail.send(msg)

	##########################################################################
	# Function Name: send_lpr
	#
	# Parameters: self, lpr_server, filename1, filename2, filename3,
	#			  filename4, filename5
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Grabs the lpr_server from the config file to find out what the IP
	#	address and port that the license plate reading server is using.
	#	Creates an array for the image files that are going to be sent over
	#	to the license plate reading server.
	#	Create a thread with the arguments [app, image_irl, files] and 
	#	targets the send_request function. Start the thread.
	#
	##########################################################################
	def send_lpr(self, lpr_server, filename1, filename2, filename3, filename4, filename5):
		#Send images to the lpr server
		image_url = "http://" + lpr_server + "/get_images"
		files=[
		('image1', (filename1, open(os.path.join(filename1), 'rb'), 'image/jpg')),
		('image2', (filename2, open(os.path.join(filename2), 'rb'), 'image/jpg')),
		('image3', (filename3, open(os.path.join(filename3), 'rb'), 'image/jpg')),
		('image4', (filename4, open(os.path.join(filename4), 'rb'), 'image/jpg')),
		('image5', (filename5, open(os.path.join(filename5), 'rb'), 'image/jpg')),
		]
		# async_result = pool.apply_async(self.send_request, (app, image_url, files))
		# value = async_result.get()
		thr = Thread(target=self.send_request, args=[app, image_url, files])
		thr.start()
		return 

	##########################################################################
	# Function Name: send_request()
	#
	# Parameters: self, app, image_url, files
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	Set flask's app context to here and do a request post to the license
	#	plate reading server with the image files taken form the send_lpr
	#	function. When the post comes back, we are expecting different 
	#	messages however we are specifically looking for "Open" and "Error"
	#	If the return value from the post request is "Open", set the global
	#	gd_open to True and call the agdopen() function passing in the "flocl"
	#	argument. Once it is done running the agdopen() function, we set the
	#	global gd_open to None. If the global gd_open was True, print to
	#	the terminal that the garage door is already opening. If the return
	#	value from the post request was an "Error", print "Error" and return
	#	to the motion detection. If the return value was neither "Open" or
	#	"Error", print "Probably Empty" in the terminal which means that 
	#	the license plate server did not find any license plate from the
	#	image.
	#
	##########################################################################
	def send_request(self, app, image_url, files):
		global gd_open
		with app.app_context():
			r = requests.post(image_url,files=files)
			checker = r.text

			#Depending on checker, we will turn on LED or not
			if (checker == "Open"):
				if (gd_open is None):
					gd_open = True
					self.agdopen(flock)
					gd_open = None
				elif(gd_open is True):
					print "Garage door is already opening"
					return
			elif(checker == "Error"):
				print "Error"
				return
			else:
				print "Probably Empty"
				return

	##########################################################################
	# Function Name: agdopen()
	#
	# Parameters: self, flock
	#
	# Posted Data: None
	#
	# Return Value: None
	#	
	# Description:
	#	When the function is called, we first check if flock (force lock) is
	#	True or False. If flock is True, we don't turn on the LED lights. If
	#	flock is False, we go into a while loop and call the gd_sense() 
	#	function, which turns on the LED lights. Once the gd_sense() function
	#	is done running, we set "wait" variable to None to get out of the
	#	while loop. Else for any possuble error, return back to the motion
	#	detector.
	#
	##########################################################################
	def agdopen(self, flock):
		wait = True
		#Check if force lock is True or False
		#if its true, dont turn on LED
		#if false, then turn on LED
		if (flock is True):
			return
		elif (flock is False):
			while wait:
				gd_sense()
				wait = None
		else:
			return
		return

##########################################################################
# Class Name: Camera
#
# Function Names: create_thread()
#				  get_frame()
#				  livestream()
#
# Parameters: object
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	The Camera class is used for the livestreaming a motion jpeg stream
#	that is used in the livestream page. It is used to create a thread to
#	turn on the camera and start capturing images rapidly and return the
#	frames back to the generate_frames() function.
#
##########################################################################
class Camera(object):
    thread = None
    frame = None
    start = 0

    ##########################################################################
    # Function Name: create_thread()
    #
    # Parameters: self, brightness, hflip, vflip
    #
    # Posted Data: None
    #
    # Return Value: None
    #
    # Description:
    #	Takes the parameters to be sent to the thread with the target function
    #	livestream(). Start the thread after and ensure that while the frame
    #	is None, don't sleep.
    #
    ##########################################################################
    def create_thread(self, brightness, hflip, vflip):
        if Camera.thread is None:
            #create the thread
            Camera.thread = Thread(target=self.livestream, args=[brightness, hflip, vflip])
            Camera.thread.start()

            #Wait until the frame is available
            while self.frame is None:
                time.sleep(0)

    ##########################################################################
    # Function Name: get_frame()
    #
    # Parameters: self, brightness, hflip, vflip
    #
    # Posted Data: None
    #
    # Return Value:
    #	self.frame
    #
    # Description:
    #	The function is called from the generate_frames() function. Passing 
    #	in the brightness, hflip, and vflip arguments. Calls the
    #	create_thread() function and passes in the brightness, hflip, and
    #	vflip parameters. Returns the frame feed from the camera.
    #
    ##########################################################################
    def get_frame(self, brightness, hflip, vflip):
        Camera.start = time.time()
        self.create_thread(brightness, hflip, vflip)
        return self.frame

    ##########################################################################
    # Function Name: livestream()
    #
    # Parameters: cls, brightness, hflip, vflip
    #
    # Posted Data: None
    #
    # Return Value: none
    #
    # Description:
    #	Sets up the picamera for usage. Uses the settings sent from the
    #	previous functions. Creates a stream for later usage. Use the
    #	picameras continuous capture to capture images rapidly and send it
    #	to the stream that was created. We then store the frame to be shown
    #	and read that frame and send it to the get_frame() function to 
    #	return that frame to the generate_frame() function. We then reset the
    #	stream for the next frame. When there are no more users connected to
    #	the livestream page, after 3 seconds, it will break out of the loop
    #	and turn off the camera as well as closing the thread.
    #
    ##########################################################################
    @classmethod
    def livestream(cls, brightness, hflip, vflip):
        with picamera.PiCamera() as camera:
            # camera setup
            camera.resolution = (640, 480)
            camera.brightness = brightness
            camera.hflip = hflip
            camera.vflip = vflip
            stream = io.BytesIO()
            for foo in camera.capture_continuous(stream, 'jpeg',
                                                 use_video_port=True):
                #store the frame to be shown
                stream.seek(0)
                cls.frame = stream.read()

                #reset the stream for the next frame
                stream.seek(0)
                stream.truncate()

                #Stop the thread after 3 seconds of no clients
                if time.time() - cls.start > 3:
                    break
        cls.thread = None


##########################################################################
#
#							HELPER FUNCTIONS
#
##########################################################################

##########################################################################
# Function Name: load_user()
#
# Parameters: username
#
# Posted Data: None
#
# Return Value:
#	String - _id
#	String - _usename
#	String - _password
#
# Description:
#	Is a callback function from the flask-login library that is used to
#	reload the user object from the user ID stored in the session. Checks
#	if the user exist in the database. If it doesn't exist, return None
#	(which means that the user will get an error message when trying to 
#	log in). If the user exist, then get the _id in unicode, username
#	and password and send to the User class to handle it.
#
##########################################################################
@login_manager.user_loader
def load_user(username):
	user_id = mongo.db.user.find_one({"username": username})
	if not user_id:
		return None
	else:
		_id = unicode(user_id["_id"])
		_username = user_id["username"]
		_password = user_id["password"]
	return User(_id, _username, _password)

##########################################################################
# Function Name: generate_frames()
#
# Parameters: camera, brightness, hflip, vflip
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	The function takes in a camera object, brightness, hflip, and vflip.
#	When the function gets called, it goes straight into a while loop and
#	grabs the frame from the get_frame() function inside the Camera Class.
#	It then yields the frame with the content type of image/jpeg. The
#	yield keyword ensures that as soon as the 1 frame is sent, it gets
#	erased. In this case, we only needed to show that 1 frame in less than
#	a second and move on to the next frame.
#
##########################################################################
def generate_frames(camera, brightness, hflip, vflip):
    #Video streaming generator function
    while True:
        frame = camera.get_frame(brightness, hflip, vflip)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

##########################################################################
# Function Name: reset_pass_email()
#
# Parameters: remail, firstname, lastname, link
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	The function takes in remail, firstname, lastname, and link as its 
#	parameters. We create a variable to store our email message inside
#	msg. We set the subject line, sender, and recipients. We then use html
#	as our body because we are adding in a link for the users to click on
#	to send them to the reset password page. Send the email to the user.
#
##########################################################################
def reset_pass_email(remail, firstname, lastname, link):
	#Send reset password email
	msg = Message("Hello " + firstname + " " + lastname,
		sender=Mail_User,
		recipients=[remail])

	msg.html = "You have requested to reset your password. If you did not request to reset your password, you don't have to do anything. " + \
	"Otherwise, click the link below to begin the process to reset your password." + \
	"You have 30 minutes before the link expires." + "<br><br>" + \
	link + "<br><br><br>" + "Please do not reply to this email."

	mail.send(msg)
	return

##########################################################################
# Function Name: gd_sense()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	Uses the sense hat to first show a message "Opening". Then counts from
#	3 to 0 for each second for each number. Then show the message 
#	"Opened", then count from 9 to 0 for each second for each number. 
#	Then show the message "Closing", then count from 3 to 0 for
#	each second. Then show the message "Closed", then clear the sensehat.
#	This function is used as a replacement for the garage door.
#
##########################################################################
def gd_sense():
	#Turns on the sensehat(LED lights portion)
	sense = SenseHat()
	sense.show_message("Opening", text_colour=[0, 255, 0], scroll_speed=0.03)
	for i in reversed(range(1,4)):
		randr = randint(20,255)
		randg = randint(20,255)
		randb = randint(20,255)
		sense.show_letter(str(i), text_colour=[randr,randg,randb])
		time.sleep(1)
	sense.show_message("Opened", text_colour=[0, 255, 0], scroll_speed=0.03)

	for i in reversed(range(0,10)):
		randr = randint(20,255)
		randg = randint(20,255)
		randb = randint(20,255)
		sense.show_letter(str(i), text_colour=[randr,randg,randb])
		time.sleep(1)

	sense.show_message("Closing", text_colour=[255, 0, 0], scroll_speed=0.03)
	for i in reversed(range(1,4)):
		randr = randint(20,255)
		randg = randint(20,255)
		randb = randint(20,255)
		sense.show_letter(str(i), text_colour=[randr,randg,randb])
		time.sleep(1)
	sense.show_message("Closed", text_colour=[255, 0, 0], scroll_speed=0.03)
	sense.clear()
	
##########################################################################
# Function Name: create_savefile()
#
# Parameters: save_location
#
# Posted Data: None
#
# Return Value:
#	String - filename (video)
#	String - filename (image)
#
# Description:
#	When the function is called a variable is passed to it called 
#	save_location. The function is only expecting save_location to be
#	either "video" or "image". If save_location is equal to "video", then
#	create a filename with the location for the video files (videos/). If 
#	save_location is equal to "image", then create a filename with the 
#	location for the image files (motion-images/). The filename is in the
#	format "Year-Month-Day,hourminutesecond.[h264/jpeg]". Depending on the
#	save_location the extension would either be .h264 or .jpeg. An example
#	would be "2016-04-01,0638011.jpeg".
#
##########################################################################
def create_savefile(save_location):
	#if the requested filename is for a video, create the filename for video
	#else if its image, create the filename for image
	if (save_location == "video"):
	    dateTime = time.strftime("%Y-%m-%d,%I%M%S")
	    location = "videos/"
	    filename = location + dateTime  + ".h264"
	    return filename
	elif (save_location == "image"):
		dateTime = time.strftime("%Y-%m-%d,%I%M%S")
		location = "motion-images/"
		filename = location + dateTime  + ".jpeg"
		return filename
	else:
		raise Exception("Incorrect save location")

##########################################################################
# Function Name: checkWhitespace()
#
# Parameters: word
#
# Posted Data: None
#
# Return Value:
#	Boolean - checker
#
# Description:
#	The function takes in the "word" parameter passed in when it is called.
#	It then checks for all types of whitespaces including \t, \n, \f, and
#	\v. If the word that was given have no whitespaces, set checker to 
#	True and return checker. If there is a whitespace from the word given,
#	then set checker to False and return checker.
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

##########################################################################
# Function Name: get_token()
#
# Parameters: token, expiration
#
# Posted Data: None
#
# Return Value:
#	String - serializedToken
#	
# Description:
#	The function takes in the "token" and "expiration" parameter when it is
#	called. The "token" parameter is a random integer between 0-200000. 
#	The "expiration" parameter is always 1800 seconds (30 minutes). This
#	means that the token created will only last 30 minutes and past that
#	time, when it is decoded, it will give a Signature Expired error. It
#	then returns a tokenized string. The function uses the flask's secret
#	key to create the token.
#
##########################################################################
def get_token(token, expiration=1800):
	#Create token
	s = Serializer(app.secret_key, expiration)
	serializedToken = s.dumps(token)
	return serializedToken

##########################################################################
# Function Name: verify_token()
#
# Parameters: token
#
# Posted Data: None
#
# Return Value:
#	Int - data
#	String - "Signature Expired"
#	String - "Bad Signature"
#	
# Description:
#	The function takes in the "token" parameter and verifies the token
#	that was previously created by the get_token function. The function
#	uses the flask's secret key to decode the token. We put the decoder
#	inside a try and except code to catch errors. If the data that is
#	decoded is correct, return the data. If the data has an error, return
#	with the appropriate error message.
#
##########################################################################
def verify_token(token):
	#Verifies token
	s = Serializer(app.secret_key)
	try:
		data = s.loads(token)
	except SignatureExpired:
		return "Signature Expired"
	except Badsignature:
		return "Bad Signature"
	return data

##########################################################################
# Function Name: username_to_userid()
#
# Parameters: username
#
# Posted Data: None
#
# Return Value:
#	ObjectID - user_id
#	
# Description:
#	The function takes in the "username" parameter when it is called and
#	uses it to try and find a user in the database with the same username.
#	It returns the user_id of that username.
#
##########################################################################
def username_to_userid(username):
	#Get the userid of the user from their username
	find_user = mongo.db.user.find_one({"username": username})
	user_id = find_user["_id"]
	return user_id

##########################################################################
# Function Name: string_split_res()
#
# Parameters: resolution
#
# Posted Data: None
#
# Return Value:
#	List - [int(width), int(height)]
#	
# Description:
#	The function takes in the "resolution" parameter when it is called. It
#	splits the resolution from the "x" keyword. and stores the left side
#	as "width" and the right side as "height". For example, if resolution
#	is equal to "150x200", then when it is ran with the function, it will
#	split that string into two separate strings by "x": 150 and 200. We
#	then cast those strings into numbers and store them to width and
#	height. In this case, we will get width equal to int 150 and height
#	equal to int 200. Then we return both width and height as a list.
#
##########################################################################
def string_split_res(resolution):
	#get the width and height of the resolution
	changed_res = str(resolution)
	split = changed_res.split("x")
	width = int(split[0])
	height = int(split[1])
	return width, height

##########################################################################
# Function Name: delete_images()
#
# Parameters: None
#
# Posted Data: None
#
# Return Value: None
#	
# Description:
#	When the function is called, it checks if there are any files inside
#	the folder "motion-images". If files do exist, then delete all of
#	files inside that folder. If there are no files inside the folder,
#	then just print "Empty".
#
##########################################################################
def delete_images():
	#Deletes all the images captured by the motion detector
	folder = "motion-images"
	images = os.listdir(folder)
	if images:
		for image in images:
			os.remove(folder+"/"+image)
		return
	else:
		print "Empty"
		return

##########################################################################
#
#                                MAIN
#
##########################################################################

#Start the Flask application
if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0', threaded=True)