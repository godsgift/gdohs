import time
import threading
from openalpr import Alpr
from flask import *
from config import *
from flask.ext.pymongo import PyMongo
from flask.ext.bcrypt import Bcrypt



app = Flask(__name__)

app.config['MONGO_DBNAME'] = DB_Name
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

    lpr = license_read(filenames)
    user = mongo.db.license.find_one({"username": "testing"})
    dblicense = user['license']
    print dblicense
    #if alpr recognizes a license plate, show it ***CHANGE HARD CODED SHIT***
    if(lpr):
        print lpr
        check_match=[]
        for i in lpr:
            testing = bcrypt.check_password_hash(dblicense,i)
            check_match.append(testing)
            print i
        print check_match
        for x in check_match:
            if x is True:
                return "Open"
            else:
                return "nice try"
        return Response(json.dumps(check_match),  mimetype='application/json')
        #Check db
    #else if the list is empty, the alpr did not recognize any license plate
    elif(not lpr):
        print "LIST IS EMPTY"
        return "sdfsdfds"


    return "OK"

def test():
    print "TEST"
    for x in range(10):
        print x
        time.sleep(1)
    return "OK"

def create_savefile(num):
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
        return
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
    return

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)





# from openalpr import Alpr

# alpr = None
# try:
#     alpr = Alpr("us", "/etc/openalpr/openalpr.conf", "/home/baus/Documents/openalpr/runtime_data/")
#     #Ensures that the alpr is loaded and can be used
#     if not alpr.is_loaded():
#         print("Error loading OpenALPR")
#         sys.exit(1)
#     elif(alpr.is_loaded()):
#         alpr.set_top_n(1)
#         alpr.set_default_region('md')

#         results = alpr.recognize_file("emma.jpg")

#         license_plates=[]
#         for plate in results["results"]:
#             for candidate in plate["candidates"]:
#                 if candidate["matches_template"]:
#                     print "test"
#                 license_plates.append(candidate["plate"])
#                 print(" %12s - %2f" % (candidate["plate"], candidate["confidence"]))

        # #if alpr recognizes a license plate, show it
        # if(license_plates):
        #     print license_plates[0]
        #     #Check db
        # #else if the list is empty, the alpr did not recognize any license plate
        # elif(not license_plates):
        #     print "LIST IS EMPTY"

# finally:
#     #Releases memory
#     if alpr:
#         alpr.unload()