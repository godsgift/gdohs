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

#Mongodb Settings
app.config['MONGO_DBNAME'] = DB_Name
app.config['MONGO_USERNAME'] = DB_User
app.config['MONGO_PASSWORD'] = DB_Pass

#Flask-Mail Settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
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

@app.route("/")
def index():
	#Redirect to home page
	form = Login()
	return render_template("index.html", form=form)

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

@app.route("/showForgotPassword")
def showForgotPassword():
	form = ForgotPassword()
	#Redirect to the forgot password page
	return render_template("forgotpassword.html", form=form)

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

#Sends to this page only if user is trying to access page that requires to be logged in
@login_manager.unauthorized_handler
def unauthorized_handler():
	flash("Must be logged in to view this page.")
	return render_template("messages.html")

##########################################################################
#
#							LOGGED IN FUNCTIONS
#
##########################################################################
@app.route("/home")
@login_required
def home():
	return render_template("home.html")

@app.route("/livestream")
@login_required
def livestream():
	return render_template("live-stream.html")

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

@app.route("/downloadvideos/<filename>")
@login_required
def downloadvideos(filename):
	videos = os.listdir("videos")
	for video in videos:
		if (filename == video):
			return send_from_directory('videos', video, as_attachment=True)
	return redirect(url_for("showDownloadVideos"))

@app.route("/deletevideos/<filename>")
@login_required
def deletevideos(filename):
	folder = "videos"
	videos = os.listdir(folder)
	for video in videos:
		if (video == filename):
			os.remove(folder+"/"+filename)
	return redirect(url_for("showDownloadVideos"))

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
				if (_resolution == "320x240" or _resolution == "640x480" or _resolution == "1280x1024" 
					or _resolution == "1920x1080"):
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
						wait = True
						while wait:
							gd_sense()
							gd_open = None
							wait = None
					else:
						return redirect(url_for("showProfile"))
				elif(gd_open is True):
					flash ("LED lights are currently on")
					return redirect(url_for("showProfile"))
	return redirect(url_for("showProfile"))

@app.route("/showChangePassword")
@login_required
def showChangePassword():
	form = ChangePassword()
	return render_template("changepassword.html", form=form)

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

@app.route("/showRecordvideos")
@login_required
def showRecordvideos():
	form = Recording()
	return render_template("recordvideos.html", form=form)

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
						flash("Started recording on " + time.strftime("%Y-%m-%d %I:%M:%S") + ".")
						return render_template("recordvideos.html", form=form)
			except (PiCameraMMALError, PiCameraError, PiCameraAlreadyRecording):
				flash("Camera already in use. Please ensure that there is no one in the livestream page or stop the recording")
		else:
			flash("Error, please refresh the page and try again")
			return render_template("recordvideos.html", form=form)
	return render_template("recordvideos.html", form=form)

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

class User():
	def __init__(self, id, username, password):
		self.id = id
		self.username = username
		self.password = password

	def is_active(self):
		return True

	def is_authenticated(self):
		return True

	def is_anonymous(self):
		return False

	def get_id(self):
		return self.username

	@staticmethod
	def validate_login(pw_hash, password):
		return bcrypt.check_password_hash(pw_hash, password)

class MyMotionDetector(picamera.array.PiMotionAnalysis):
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

				end = time.time()
				print (end-start)

			elif (stop_record is True):
				time.sleep(20)
				stop_record = None
		return

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

	def send_email(self, app, msg):
		with app.app_context():
			mail.send(msg)

	def send_lpr(self, lpr_server, filename1, filename2, filename3, filename4, filename5):
		wait = True
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

class Camera(object):
    thread = None
    frame = None
    start = 0

    def create_thread(self, brightness, hflip, vflip):
        if Camera.thread is None:
            #create the thread
            Camera.thread = Thread(target=self.livestream, args=[brightness, hflip, vflip])
            Camera.thread.start()

            #Wait until the frame is available
            while self.frame is None:
                time.sleep(0)

    def get_frame(self, brightness, hflip, vflip):
        Camera.start = time.time()
        self.create_thread(brightness, hflip, vflip)
        return self.frame

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

def generate_frames(camera, brightness, hflip, vflip):
    #Video streaming generator function
    while True:
        frame = camera.get_frame(brightness, hflip, vflip)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

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
	return

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
	#Create token
	s = Serializer(app.secret_key, expiration)
	serializedToken = s.dumps(self)
	return serializedToken

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

def username_to_userid(username):
	#Get the userid of the user from their username
	find_user = mongo.db.user.find_one({"username": username})
	user_id = find_user["_id"]
	return user_id

def string_split_res(resolution):
	#get the width and height of the resolution
	changed_res = str(resolution)
	split = changed_res.split("x")
	width = int(split[0])
	height = int(split[1])
	return width, height

def delete_images():
	#Deletes all the images captured by the motion detector
	folder = "motion-images"
	images = os.listdir(folder)
	if images:
		for image in images:
			os.remove(folder+"/"+image)
		return
	else:
		raise OSError("Empty")

if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0', threaded=True)