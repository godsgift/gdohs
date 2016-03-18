# from flask import *
# import requests

# app = Flask(__name__)

# @app.route("/")
# def index():
# 	return render_template("index.html")

# @app.route("/test")
# def test():
	# url = "http://192.168.152.129:5001/test2"
# 	test=[]

# 	data="{1:'Hello there','uhhhh lol'}"

# 	data2="Well then lol"

# 	test.append(data)
# 	test.append(data2)

	# files= {'media': open('test.jpg', 'rb')}

	# r = requests.post(url,files=files)
# 	# r2 = requests.post(url,data=data2)

# 	return render_template("signupsuccess.html")

# if __name__ == "__main__":
# 	app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
import requests
import time

url = "http://192.168.152.129:5001/test2"

#files= {'file': ("test.jpg", open('test.jpg', 'rb'))}

files=[
('images', ('test.jpg', open('test.jpg', 'rb'), 'image/jpg')),
('images3', ('test2.jpg', open('test.jpg', 'rb'), 'image/jpg'))
]

data="test.jpg"
r2 = requests.post(url,data=data)
time.sleep(1)
r = requests.post(url,files=files)