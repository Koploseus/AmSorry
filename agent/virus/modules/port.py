# -*- coding: utf-8 -*-
import socket
import sys
import time
import requests
import utils

def run():
        remoteServerIP = socket.gethostbyname(socket.gethostname())

        # Petite banniere
        utils.send_output (("-" * 60))
        utils.send_output (("Scan en cours de l'IP : ", remoteServerIP))
        utils.send_output (("-" * 60))

        # Range des ports à scanner
        for port in range(1, 9999):
                try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#CREATION DU SOCKET
                        sock.settimeout(0.001)
                        result = sock.connect_ex((remoteServerIP, port))#CONNEXION DU SOCKET SUR L'IP DONNE ET LE PORT DE LA BOUCLE
                        if result == 0:
                                utils.send_output (("Port {}: 	 open ".format(port)+socket.getservbyport(port)))#AFFICHE LE PORT PLUS L'ETAT ET LE SERVICE
                        sock.close()
                #GESTION DES ERREURS
                except socket.gaierror:
                        print("")
                        #utils.send_output (('Le nom d\'hôte n\'a pas pu être résolu.'))

                except socket.error:
                        print("")
                        #utils.send_output (("Connexion impossible"))
        utils.send_output(("Fin du scan de ports !"))
