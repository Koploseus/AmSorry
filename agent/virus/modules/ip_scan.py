# -*- coding: utf-8 -*-
import socket
import os
import sys
import time
import subprocess
import utils


def run():
        utils.send_output("Scanning the network")
        
        #Execution de la commande arp -a
        commande = ["arp", "-a"]
        cedric = subprocess.Popen(commande, shell=True, stdout=subprocess.PIPE)        
        text = cedric.stdout.read()

        #On découpe la variable text pour pouvoir envoyer au terminal morceau par morceau
        textSplit = text.split("\r\n")
        for line in textSplit:
                print(line)
                utils.send_output((line))

        utils.send_output (("End of the Scan"))


