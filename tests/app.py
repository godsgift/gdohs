import re
from flask import *
from flask.ext.pymongo import PyMongo
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import TextField
from wtforms.validators import Required, ValidationError

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
    signUpForm = SignUp()
    #only goes through if all the fields have been validated
    if signUpForm.validate_on_submit():
        return render_template('index.html')
    #return render_template('index.html', form=signUpForm)

#CLASSES
class SignUp(Form):
	username = TextField('Username', [Required(), checkWhitespace])



if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0')