##########################################################################
#
#								 IMPORTS
#
##########################################################################

import re
import picamera
import io
import time
from threading import Lock
from rpi_camera import Camera
from picamera.exc import PiCameraMMALError, PiCameraAlreadyRecording, PiCameraError
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
#need to add username and pass for db
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = Mail_User
app.config['MAIL_PASSWORD'] = Mail_Pass
#WTFORMS Settings
app.secret_key = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(app)

#Enable extensions for flask
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

rand_num = randint(0,200000)

camera = None
cameralock = Lock()

#Running db:
#mongod --dbpath data

##########################################################################
#
#							LOGGED OUT FUNCTIONS
#
##########################################################################

@app.route("/")
def index():
	form = Login()
	#Redirect to home page
	return render_template("index.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
	#STILL HAVE TO DO ERROR CHECKING
	if (request.method == 'POST'):
		form = Login(request.form)
		if(form.validate_on_submit()):
			#user input
			_username = form.username.data
			_password = form.password.data

			#check if user exist in db
			user = mongo.db.user.find_one({"username": _username})
			#from database
			if (user):

				user_id = user["_id"]
				user_name = user["username"]
				user_pass = user["password"]

				if (User.validate_login(user_pass, _password)):
					user_obj = User(user_id, user_name, user_pass)
					login_user(user_obj)
					next = request.args.get('next')
					return redirect(next or url_for("showProfile"))
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
					flash("Password reset has been sent to " + _email)
					return render_template("/forgotpassword.html", form=ForgotPassword())
			else:
				print "GOT HERE"
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

@app.route("/livestream")
@login_required
def livestream():
	return render_template("live-stream.html")

@app.route("/videostream")
@login_required
def videostream():
	return Response(generate_frames(Camera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/showRecordvideos")
@login_required
def showRecordvideos():
	form = Recording()
	return render_template("recordvideos.html", form=form)

@app.route("/startrecord", methods=['GET', 'POST'])
@login_required
def startrecord():
	form = Recording()
	if (request.method == 'POST'):
		form = Recording(request.form)
		#grab user input
		start = form.start.data
		stop = form.stop.data
		
		#User wants to start streaming
		if (start == True and stop == False):
			print "START RECORDING"
			try:
				global camera
				with cameralock:
					#get user that is currently logged in

					#get camera settings set by that user from the database

					#Start camera
					camera = picamera.PiCamera()
					camera.resolution=(640,480)
					time.sleep(2)
					camera.start_recording("test.h264")
			except (PiCameraMMALError, PiCameraError, PiCameraAlreadyRecording):
				flash("Camera already in use. Please ensure that there is no one in the livestream page or stop recording")
	return render_template("recordvideos.html", form=form)

@app.route("/stoprecord", methods=['GET', 'POST'])
@login_required
def stoprecord():
	form = Recording()
	if (request.method == 'POST'):
		form = Recording(request.form)
		#grab user input
		start = form.start.data
		stop = form.stop.data
		print "STOP RECORDING"
		if (camera is None):
			flash("Camera is not recording. Please start recording before stopping it.")
		else:
			global camera
			with cameralock:
				camera.stop_recording()
				camera.close()
				camera = None

	return render_template("recordvideos.html", form=form)


@app.route("/showDownloadvideos")
@login_required
def downloadvideos():
	return render_template("video.html")

@app.route("/showSettings")
@login_required
def showSettings():
	form = CamSettings()
	#Find current user
	username = current_user.username
	find_user = mongo.db.user.find_one({"username": username})
	user_id = find_user["_id"]
	#check if user had set a settings previously
	check_user = mongo.db.settings.find_one({"user_id": user_id})
	#Show the user the current settings to the HTML
	brightness = check_user["brightness"]
	resolution = check_user["resolution"]
	hflip = check_user["hflip"]
	vflip = check_user["vflip"]
	return render_template("settings.html", form=form, 
		brightness=brightness, resolution=resolution, hflip=hflip, vflip=vflip)

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
			if (_brightness >= 0 or _brightness <= 100):
				if (_resolution == "320x240" or _resolution == "640x480" or _resolution == "1280x1024" 
					or _resolution == "1920x1080"):
					if (_hflip == True or _hflip == False):
						if (_vflip == True or _vflip == False):
							#Find the logged in user that is trying to access this
							username =  current_user.username
							find_user = mongo.db.user.find_one({"username": username})
							#Get user_id from the logged in user
							user_id = find_user["_id"]
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
								flash("Error, please try again.")
								return render_template("settings.html", form=form)
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
			return redirect(url_for("showSettings"))
	else:
		return redirect(url_for("showSettings"))
	return redirect(url_for("showSettings"))

@app.route("/showProfile")
@login_required
def showProfile():
	form = ChangePassword()
	return render_template("profile.html", form=form)

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

##########################################################################
#
#							HELPER FUNCTIONS
#
##########################################################################
#Adds the user into the session
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


def create_savefile():
    dateTime = time.strftime("%Y-%m-%d,%I%M")
    location = "videos/"
    filename = location + dateTime  + ".h264"
    return filename
	    
def generate_frames(camera):
    """Video streaming generator function."""
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

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

def verify_token(token):
	s = Serializer(app.secret_key)
	try:
		data = s.loads(token)
	except SignatureExpired:
		return "Signature Expired"
	except Badsignature:
		return "Bad Signature"
	return data

def reset_pass_email(remail, firstname, lastname, link):
	msg = Message("Hello " + firstname + " " + lastname,
		sender=Mail_User,
		recipients=[remail])

	msg.html = "You have requested to reset your password. If you did not request to reset your password, you don't have to do anything. " + \
	"Otherwise, click the link below to begin the process to reset your password." + \
	"You have 30 minutes before the link expires." + "<br><br>" + \
	link + "<br><br><br>" + "Please do not reply to this email."

	mail.send(msg)
	return

if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0', threaded=True)