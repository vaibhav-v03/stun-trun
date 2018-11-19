import pyaudio

class Client():
    def start(self):
        p = pyaudio.PyAudio()
        CHUNK = 1024
        out_stream = p.open(format=pyaudio.paInt16,
                            channels=1,
                            rate=16000,
                            input=True,
                            frames_per_buffer=CHUNK)
        while True:
            data = 'msg '
            data += out_stream.read(CHUNK)
            print(str(data))


c = Client()
c.start()