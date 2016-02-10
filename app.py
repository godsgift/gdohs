from flask import *
from flask.ext.pymongo import PyMongo
from flask.ext.security import Security

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'gdohs'

mongo = PyMongo(app)

#Running db:
#mongod --dbpath data


@app.route("/")
def index():
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

	#Add the new user to the
	result = mongo.db.user.insert_one(
		{
			"username": _username,
			"password": _password,
			"email": _email,
			"firstname": _firstname,
			"lastname": _lastname
		}
	)

	return json.dumps({'html':'<span>Sign up Successful</span>'})


if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')