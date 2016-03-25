import time
import threading
from openalpr import Alpr
from flask import *
from config import *
from flask.ext.pymongo import PyMongo
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)

app.config['MONGO_DBNAME'] = DB_Name
app.config['MONGO_USERNAME'] = DB_User
app.config['MONGO_PASSWORD'] = DB_Pass
app.config['MONGO_HOST'] = DB_IP
app.config['MONGO_PORT'] = DB_Port

app.secret_key = SECRET_KEY

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

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
        
        #If any of the license plates mathces, send the open signal to the rpi
        #to turn on the LED lights, else return false signal
        for x in check_match:
            if x is True:
                return "Open"
            else:
                return "False"
    #else if the list is empty, the alpr did not recognize any license plate
    elif(not lpr):
        print "EMPTY"
        return "Empty"
    #else if the lpr returns error, send back error
    elif(lpr == "Error"):
        print "ERROR"
        return "Error"
    #If it did not process any of the above, return an error
    return "Error"

def create_savefile(num):
    #Create filename for the images that are sent here from the rpi
    dateTime = time.strftime("%Y-%m-%d,%I%M%S"+str(num))
    location = "motion-images/"
    filename = location + dateTime  + ".jpeg"
    return filename

def license_read(filenames=[]):
    print "IN LICENSE_READ"
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

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)