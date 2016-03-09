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
            #create the thread
            Camera.thread = threading.Thread(target=self.livestream)
            Camera.thread.start()

            # wait until frames start to be available
            while self.frame is None:
                time.sleep(0)

    def get_frame(self):
        Camera.start = time.time()
        self.create_thread()
        return self.frame

    @classmethod
    def livestream(cls):
        with picamera.PiCamera() as camera:
            # camera setup
            camera.resolution = (640, 480)
            camera.framerate = 24
            stream = io.BytesIO()
            for foo in camera.capture_continuous(stream, 'jpeg',
                                                 use_video_port=True):
                #store the frame to be shown later
                stream.seek(0)
                cls.frame = stream.read()

                #reset the stream for the next frame
                stream.seek(0)
                stream.truncate()

                #Stop the thread after 3 seconds of no clients
                if time.time() - cls.start > 3:
                    break
        cls.thread = None

    