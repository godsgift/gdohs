import unittest
import re
import time
import app
from pymongo import MongoClient

class gdohs_tests(unittest.TestCase):
	#Test the create savefile function
	def test_create_savefile(self):
		datetime = time.strftime("%Y-%m-%d,%I%M%S")
		filenameVideo = "videos/" + datetime + ".h264"
		filenameImage = "motion-images/" + datetime + ".jpeg"

		self.assertEqual(app.create_savefile("video"), filenameVideo)
		self.assertEqual(app.create_savefile("image"), filenameImage)

		with self.assertRaises(Exception):
			app.create_savefile("GIF")

	#Test the check whitespace function
	def test_checkWhitespace(self):
		self.assertTrue(app.checkWhitespace("TEST"), True)
		self.assertFalse(app.checkWhitespace("TE ST"), False)

	#Test the string split res function
	def test_string_split_res(self):
		self.assertEqual(app.string_split_res("640x480"), (640,480))
		
		with self.assertRaises(ValueError):
			app.string_split_res("freexere")

if __name__ == '__main__':
	unittest.main()