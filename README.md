# GDOHS (Garage Door Opener and Home Surveillance)

Summary
=======

A proof-of-concept project for a home surveillance camera with an automatic garage door opener where an LED light is used to represent the garage door.

The project is to build a web application that allows the user to live stream, record, and turn on the LED lights.

The web application includes:
1. Signup
2. Login/Logout
3. Forget Password/Reset Password
4. Profile Page
5. Live-stream page
6. Video recording page
7. Camera settings page
8. Home page
9. Download/Delete video page


Hardware Requirements
=====================
1. Raspberry Pi Model 2B
2. Picamera
3. Sensehat
4. USB 64GB/128GB
5. USB Wireless Adapter
6. Lightweight server (laptop/desktop)

Software Requirements
=====================
1. Raspberry pi - Raspbian GNU/Linux 8 (Jessie)
2. Laptop/desktop server - Preferred (Ubuntu) but Mint Cinnamon 17.3 was used for this project.
3. Python 2.7.9 programming language installed (usually packaged with Raspberry pi and Mint)

External Library Requirements
=============================

Before running the program, please ensure that all the required external libraries are installed for both machines.

1. **Raspberry Pi External Library Dependencies**
	- Flask
	- Flask-Login
	- Flask-Bcrypt
	- Flask-Mail
	- Flask-WTF
	- Flask-Pymongo
	- Pymongo
	- Mongodb
	- Picamera (Usually installed when picamera is connected to the raspberry pi)
	- Sensehat (Usually installed when sensehat is connected to the raspberry pi)
	- itsdangerous

2. **Laptop/Desktop Server External Library Dependencies**
	- Flask
	- Flask-Bcrypt
	- Flask-Pymongo
	- Pymongo
	- OpenALPR

Usage:
======
Once all the external libraries have been installed and tested to be working, you may run the following programs included in the package.

Note: Ensure that "SECRET_KEY" inside both the config file matches.

1. **Raspberry Pi**
	- Ensure that the necessary changes have been made to the configuration file before running the program.
	- On the raspberry pi, we will start the database instance first.
	- mongod --dbpath data --smallfiles --auth
	- After starting the MongoDB instance, we will now create our database.
	- **python dbscripts.py**
	- Once we have created our database, we can now start our flask application
	- **sudo python app.py**

2. **Laptop/Desktop Server**
	- Ensure that the necessary changes have been made to the configuration file before running the program
	- We will only need to run the license plate reading server in this machine
	- **sudo python lprserver.py**
