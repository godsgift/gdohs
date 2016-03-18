from flask import *
from werkzeug import secure_filename
import os
import time

UPLOAD_FOLDER = '/home/baus/Documents/flask/sent'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def index():
	return render_template("index.html")

@app.route("/test2", methods=['GET', 'POST'])
def test():
	if (request.method == 'POST'):
		filenames=[]
		data = request.data
		print data
		filenames.append(data)
		time.sleep(0.5)
		files = request.files
	
		print files['images']
		print files['images3']
		print "DATA IS THIS"
		print filenames
		with open("sent/test.jpg", 'wb') as f:
			for chunk in files['images']:
				f.write(chunk)

	return render_template("signupsuccess.html")

	

if __name__ == "__main__":
	app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)