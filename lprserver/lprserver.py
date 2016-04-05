##########################################################################
# SOURCE FILE:  lprserver.py
#
# AUTHOR:       ELTON SIA
#
# PROGRAM:      A license plate reading server. The program takes in 
#               images and uses the alpr (a license plate reading library)
#               and tries to find characters from the images. Depending
#               on what it finds, it will return the appropriate message.
#
# DATE:         April 07, 2016
#
# USAGE:        Ensure that the values in the config file have been
#               changed. The mongodb instance is running from the 
#               Raspberry PI.
#                          
#               sudo python lprserver.py
#
##########################################################################

##########################################################################
#
#                                IMPORTS
#
##########################################################################
import time
import threading
from openalpr import Alpr
from flask import *
from config import *
from flask.ext.pymongo import PyMongo
from flask.ext.bcrypt import Bcrypt

##########################################################################
#
#                                GLOBAL
#
##########################################################################
app = Flask(__name__)

app.config['MONGO_DBNAME'] = DB_Name
app.config['MONGO_USERNAME'] = DB_User
app.config['MONGO_PASSWORD'] = DB_Pass
app.config['MONGO_HOST'] = DB_IP
app.config['MONGO_PORT'] = DB_Port

app.secret_key = SECRET_KEY

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

##########################################################################
#
#                                FUNCTIONS
#
##########################################################################

##########################################################################
# Function Name: get_images()
#
# Parameters: None
#
# Posted Data:
#   Files - image
#
# Return Values:
#   String - "Open"
#   String - "Error"
#   String - "Empty"
#   String - "False"
#
# Description:
#   The function is triggered when a post request has been initiated from
#   another end. It expects to receive 5 image files and saves them
#   locally when they first arrive. The create_savefile() function is called
#   to save the images locally. We then store the names of those images
#   to a list called "filenames". We then send those filenames into the
#   license_read() function and returns either an empty list or a list
#   of possible license plates in String. We then get all the license
#   plate from the database to be matched later on. We then check if 
#   the license_read() function has returned an empty list or a list
#   of possible license plates. If it returned a list of possible license
#   plates, We then compare the possible license plates to the license
#   plate inside the database. Keep in mind that the license plates in
#   the database are hashed and salted hence the usage of bcrypt compare
#   method. We then store the results inside the check_match list. We
#   go into a for loop and check if any of the matches is True or False.
#   If its True, return the "Open" signal, otherwise return the "False"
#   signal. If the license_read() function returned an empty list, return
#   the "Empty" signal. If the license_read() function returned an error,
#   return the "Error" signal.
#
##########################################################################
@app.route("/get_images", methods=['GET', 'POST'])
def get_images():
    filenames=[]
    if (request.method == 'POST'):
        #Get images sent from the RPI server
        image = request.files

        #Save the images locally
        for x in range(1,6):
            filename = create_savefile(x)
            filenames.append(filename)
            with open(filename, "wb") as f:
                for chunk in image["image" + str(x)]:
                    f.write(chunk)

    #List of license plate characters that were gotten from image
    #could be empty which means that the alpr did not find any license plates
    lpr = license_read(filenames)

    #Get all the license plates to try and match it with the user
    results = mongo.db.license.find({},{"license":1,"_id":0})

    #Grab user id then license plate
    #if alpr recognizes a license plate, add it onto the check_match list
    if(lpr):
        check_match=[]
        #This will slow down depending on how many license plates are in the database
        #but this app is meant for about 5 people so about 5 license plates
        for result in results:
            dblicense = result["license"]
            #Check if any of the license plate from the images
            #matches the hashed license plate in the database
            #and add them onto the check_match list
            for i in lpr:
                check_license = bcrypt.check_password_hash(dblicense,i)
                check_match.append(check_license)
        
        #If any of the license plates matches, send the open signal to the rpi
        #to turn on the LED lights, else return false signal
        for x in check_match:
            if x is True:
                return "Open"
            else:
                return "False"
    #else if the list is empty, the alpr did not recognize any license plate
    elif(not lpr):
        return "Empty"
    #else if the lpr returns error, send back error
    elif(lpr == "Error"):
        return "Error"
    #If it did not process any of the above, return an error
    return "Error"

##########################################################################
# Function Name: create_savefile()
#
# Parameters: num
#
# Posted Data: None
#
# Return Values:
#   String - filename
#
# Description:
#   The function takes in a "num" parameter which is passed in when the
#   function is called. It creates a string for the filename with the
#   location. The passed in variable "num" is used as part of the
#   filename. An example filename would be "2016-04-01,0638014.jpeg".
#
##########################################################################
def create_savefile(num):
    #Create filename for the images that are sent here from the rpi
    dateTime = time.strftime("%Y-%m-%d,%I%M%S"+str(num))
    location = "motion-images/"
    filename = location + dateTime  + ".jpeg"
    return filename

##########################################################################
# Function Name: license_read()
#
# Parameters: filenames
#
# Posted Data: None
#
# Return Values:
#   List - license_plates
#
# Description:
#   The function takes in a "filenames" parameter that is passed in when
#   the function is called. We first set the alpr into None, and then
#   proceed into creating an Alpr instance with the correct paths for
#   the config file and the runtime_data for the Alpr to use. We then
#   check if the alpr instance has been loaded. If it is not loaded, print
#   an error message and return "Error". If the alpr is loaded, we set the
#   reader to return only the top 1 license plate matches. We then set the
#   default region to "md" (MaryLand). We used this as our region because
#   it has some commonalities with the BC license plates. We then go into
#   a for loop to get the license plates from the images and store it
#   into a list called license_plates. We then return the list.
#
##########################################################################
def license_read(filenames=[]):
    alpr = None
    #tell alpr which country license plate to use and where to find the openalpr.conf file and the
    #runtime_data folder
    alpr = Alpr("us", "/etc/openalpr/openalpr.conf", "/home/baus/Documents/openalpr/runtime_data/")
    #Ensures that the alpr is loaded and can be used
    if not alpr.is_loaded():
        print("Error loading OpenALPR")
        return "Error"
    elif(alpr.is_loaded()):
        alpr.set_top_n(1)
        alpr.set_default_region('md')

        license_plates=[]
        #for all the images that was sent, check if license plate exists
        for x in range(5):
            results = alpr.recognize_file(filenames[x])
            for plate in results["results"]:
                for candidate in plate["candidates"]:
                    #Appends the license plate to the list
                    #Appends nothing if it didnt find any license plate
                    license_plates.append(candidate["plate"])
        return license_plates
    return "Error"

##########################################################################
#
#                                MAIN
#
##########################################################################

#Starts the Flask application.
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)