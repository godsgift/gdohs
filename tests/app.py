import re
from flask import *
from flask.ext.pymongo import PyMongo
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import TextField, PasswordField, validators
from wtforms.validators import Required, Length, Email, ValidationError, Regexp

app = Flask(__name__)

#Mongodb Settings
app.config['MONGO_DBNAME'] = 'gdohs'

#WTFORMS Settings
app.secret_key= 'testing'


#Enable extensions for flask
mongo = PyMongo(app)


#Running db:
#mongod --dbpath data

@app.route("/")
def index():
	#Redirect to home page
	signUpForm = SignUp()
	return render_template("test.html", form=signUpForm)



def checkWhitespace(form, field):
	#Checks for all types of whitespaces including \t, \n, \f, \v
	userInput = field.data
	
	ws = re.search('[\s+]', userInput)
	#True for no whitespace
	checker = True

	#If there is whitespace then set checker to false
	if (ws):
		checker = False
		if (checker == False):
			raise ValidationError("Cannot have whitespaces")

	return render_template('index.html')

@app.route('/submit', methods=('GET', 'POST'))
def submit():
	if (request.method == 'POST'):
		form = SignUp(request.form)

		if form.validate_on_submit():
			username = form.username.data
			print username
			print "Username VALIDATED"
		else:
			print"USERNAME FAILED"
			return render_template('test.html', form=form)
	return render_template('test.html', form=SignUp())

    #return render_template('index.html', form=signUpForm)

#CLASSES
class SignUp(Form):
	username = TextField('Username', validators=[Required("Please provide a username without any spaces"),
		Length(min=4, max=20), Regexp(r'^[\w.@+-]+$')])



if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')