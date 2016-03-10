import time
import picamera
import picamera.array
import numpy as np


class MyMotionDetector(picamera.array.PiMotionAnalysis):
    def analyse(self, a):
        a = np.sqrt(
            np.square(a['x'].astype(np.float)) +
            np.square(a['y'].astype(np.float))
            ).clip(0, 255).astype(np.uint8)
        # If there're more than 10 vectors with a magnitude greater
        # than 60, then say we've detected motion
        if (a > 60).sum() > 50:
            print "taking picture"
            # camera.capture("videos/testing.jpg", use_video_port=True)
            # time.sleep(1)

with picamera.PiCamera() as camera:
    camera.resolution = (640, 480)
    camera.framerate = 30
    time.sleep(2)
    for filename in camera.record_sequence(
        ('clip%02d.h264' % i for i in range(2)), motion_output=MyMotionDetector(camera)):
        camera.wait_recording(3600)
        camera.stop_recording
    # camera.start_recording(
    #     '/dev/null', format='h264',
    #     motion_output=MyMotionDetector(camera)
    #     )
    # camera.wait_recording(30)
    # camera.stop_recording()








# class Camera(object):
# 	thread = None
# 	frame = None
# 	start = 0

# 	def create_thread(self):
# 		if Camera.thread is None:
# 			#Start a new thread for the rpi camera
			# Camera.thread = threading.Thread(target=self.recording)
			# Camera.thread.start()

# 			while self.frame is None:
# 				time.sleep(0)

# 	def get_frame(self):
# 		Camera.start = time.time()
# 		Camera.filename = self.create_savefile("h264")
# 		self.create_thread()
# 		return self.frame

# 	def create_savefile(self, filetype):
# 	    dateTime = time.strftime("%Y-%m-%d,%I%M")
# 	    location = "videos/"
# 	    filename = location + dateTime  + "." + filetype
# 	    return filename

# 	@classmethod
# 	def recording(cls):
# 		with picamera.PiCamera() as camera:
# 			#warm up camera
# 			time.sleep(2)
# 			#Camera settings
# 			camera.resolution = (640, 480)
# 			camera.framerate = 24

# 			stream = io.BytesIO()
# 			for foo in camera.capture_continuous(stream, 'jpeg',
# 			                                     use_video_port=True):

# 				#store the frame
# 				stream.seek(0)
# 				cls.frame = stream.read()

# 				# #reset stream for next frame
# 				stream.seek(0)
# 				stream.truncate()

# 				if time.time() - cls.start  > 3:
# 					break

# 		cls.thread = None