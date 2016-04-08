##########################################################################
#
#                                IMPORTS
#
##########################################################################

import unittest
import re
import time
import app
from pymongo import MongoClient

##########################################################################
#
#                                CLASSES
#
##########################################################################

##########################################################################
# Class Name: gdohs_tests
#
# Function Names: test_create_savefile()
#				  test_checkWhitespace()
#				  test_string_split_res
#
# Parameters: unittest.TestCase
#
# Posted Data: None
#
# Return Value: None
#
# Description:
#	Tests most of the helper functions that can be tested. The tests are 
#	all done in the manner of passing in the correct expected values
#	and passing in the incorrect values. This way, even if we were to
#	change the function, as long as we are expecting a specific value,
#	we are able to check whether the test passes or not.
#
##########################################################################
class gdohs_tests(unittest.TestCase):

	##########################################################################
	# Function Names: test_create_savefile()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	The test checks whether the argument passed onto the function is 
	#	either "video" or "image". Since we are only expecting 1 or the other,
	#	if the value that was passed is incorrect, then raise an exception.
	#	However, if the value that was passed was either "video" or "image",
	#	it returns the correct value and passes the test.
	#
	##########################################################################
	def test_create_savefile(self):
		datetime = time.strftime("%Y-%m-%d,%I%M%S")
		filenameVideo = "videos/" + datetime + ".h264"
		filenameImage = "motion-images/" + datetime + ".jpeg"

		self.assertEqual(app.create_savefile("video"), filenameVideo)
		self.assertEqual(app.create_savefile("image"), filenameImage)

		with self.assertRaises(Exception):
			app.create_savefile("GIF")

	##########################################################################
	# Function Names: test_checkWhitespace()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	The test checks if the returned value has a whitepsace or not. If the
	#	value that was passed in has a white space, return a False value. If
	#	the value that was passed in does not have a white space, return
	#	a True value.
	#
	##########################################################################
	def test_checkWhitespace(self):
		self.assertTrue(app.checkWhitespace("TEST"), True)
		self.assertFalse(app.checkWhitespace("TE ST"), False)

	##########################################################################
	# Function Names: test_string_split_res()
	#
	# Parameters: self
	#
	# Posted Data: None
	#
	# Return Value: None
	#
	# Description:
	#	The test ensures that the string_split_resO() function is working as
	#	intended. If the value that was passed in does not match a certain
	#	format, the test would raise a value error. It must follow the format
	#	"numberxnumber". If the correct format was given, it returns the
	#	correct value and the test passes. Otherwise, would fail.
	#
	##########################################################################
	def test_string_split_res(self):
		self.assertEqual(app.string_split_res("640x480"), (640,480))
		
		with self.assertRaises(ValueError):
			app.string_split_res("freexere")

##########################################################################
#
#                                MAIN
#
##########################################################################
if __name__ == '__main__':
	unittest.main()