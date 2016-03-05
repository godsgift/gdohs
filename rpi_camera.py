import time
import io
import threading
import picamera

class Camera(object):
    thread = None
    frame = None
    start = 0
    create_savefile = ""

    def initialize(self):
        if Camera.thread is None:
            # start background frame thread
            Camera.thread = threading.Thread(target=self._thread)
            Camera.thread.start()

            # wait until frames start to be available
            while self.frame is None:
                time.sleep(0)

    def get_frame(self):
        Camera.start = time.time()
        self.initialize()
        return self.frame

    def detect_motion(camera):
        global prior_image
        stream = io.BytesIO()
        camera.capture(stream, format="jpeg", use_video_port=True)
        pass


    @classmethod
    def _thread(cls):

        with picamera.PiCamera() as camera:
            # camera setup
            camera.resolution = (320, 240)
            stream = io.BytesIO()
            for foo in camera.capture_continuous(stream, 'jpeg',
                                                 use_video_port=True):
                # store frame
                stream.seek(0)
                cls.frame = stream.read()

                # reset stream for next frame
                stream.seek(0)
                stream.truncate()

                #Stop the thread after 3 seconds of no clients
                if time.time() - cls.start > 3:
                    stream.seek(0)
                    stream.truncate()
                    break
        cls.thread = None

    