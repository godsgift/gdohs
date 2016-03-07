import time
import io
import threading
import picamera

class Camera(object):
	thread = None
	frame = None
	start = 0

	def create_thread(self):
		if Camera.thread is None:
			#Start a new thread for the rpi camera
			Camera.thread = threading.Thread(target=self.recording)
			Camera.thread.start()

			while self.frame is None:
				time.sleep(0)

	# def get_frame(self):
	# 	Camera.start = time.time()
	# 	Camera.filename = self.create_savefile("h264")
	# 	self.create_thread()
	# 	return self.frame

	def create_savefile(self,):
	    dateTime = time.strftime("%Y-%m-%d,%I%M")
	    location = "videos/"
	    filename = location + dateTime  + "-"
	    return filename

	# @classmethod
	def recording(cls):
		with picamera.PiCamera() as camera:
			#warm up camera
			time.sleep(2)
			#Camera settings
			camera.resolution = (640, 480)
			camera.framerate = 24
			fname = cls.create_savefile()
			for filename in camera.record_sequence(
				fname + "%d.h264" % i for i in range(1,3)):
				camera.wait_recording(100)
		cls.thread = None

class MyOutput(object):
    def __init__(self, filename, stream):
        self.output_file = io.open(filename, 'wb')
        self.output_stream = sock.makefile('wb')

    def write(self, buf):
        self.output_file.write(buf)
        self.output_sock.write(buf)

    def flush(self):
        self.output_file.flush()
        self.output_sock.flush()

    def close(self):
        self.output_file.close()
        self.output_sock.close()

Camera().create_thread()