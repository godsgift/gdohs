from flask import *
from flask.ext.pymongo import PyMongo
# from flask.ext.security import Security
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'gdohs'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

#Running db:
#mongod --dbpath data


@app.route("/")
def index():
	#Redirect to home page
	return render_template("index.html")

@app.route("/home")
def home():
	#Redirect to home page
	return render_template("index.html")

@app.route("/showSignup")
def showSignup():
	#Redirect to the sign up page
	return render_template("signup.html")

@app.route("/signUp", methods=['POST'])
def signUp():
	#Grab user input
	_username = request.form['username']
	_password = request.form['password']
	_email = request.form['email']
	_firstname = request.form['firstname']
	_lastname = request.form['lastname']

	#If username already exists in database, send to sign up failure page
	if (mongo.db.user.find_one({"username": _username})):
		return render_template("signupfail.html", code=307)
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
	return render_template("signupsuccess.html", code=307)

@app.route("/checkUser", methods=['POST'])
def checkUser():
	return

@app.route("/signUpSuccessful")
def signUpSuccessful():
	return

if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')