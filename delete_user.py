import sys,json
import argparse
import os,sys
import pycurl
import getpass
import logging
from string import Template 
from StringIO import StringIO as BytesIO
def log(msg,type):
	if type == 'info':
		logging.info(" %s",msg)
	if type == 'debug':
		logging.debug(" %s",msg)
	if type == 'warning':
		logging.warning(" %s",msg)
	if type == 'exception':
		logging.exception(" %s",msg)
	if type == 'error':
		logging.error(" %s",msg)

def isPairedSwitch(value):
	isSwitch=False
	switch_arr =["-users","-admin","-url","-sslCertPath"]
	if value in switch_arr:
		isSwitch=True
	return isSwitch

def printUsage():
	log("[I] Note : This utility can be used to delete users , to delete users refer below command.","info")
	log("[I] Usage(User delete): deleteUserGroupUtil.py -users <user file path> -admin <ambari admin user> -url <ambarihosturl> [-sslCertPath <cert path>] [-debug]","info")
	log("[I] -users: Delete users specified in the given file","info")
	log("[I] -admin: Ambari Admin user ID","info")
	log("[I] -url: Ambari Admin URL","info")
	log("[I] -sslCertPath: Filepath to ssl certificate to use when Ambari Admin uses HTTPS","info")
	log("[I] -debug: Enables debugging","info")
	sys.exit(1)

def processRequest(url,usernamepassword,data,method,isHttps,certfile,isDebug):
	buffer = BytesIO()
	header = BytesIO()
	c = pycurl.Curl()
	c.setopt(c.URL, url)
	c.setopt(pycurl.HTTPHEADER, ['X-Requested-By: ambari', 'Content-Type: application/json'])
	c.setopt(pycurl.USERPWD, usernamepassword)
	c.setopt(pycurl.VERBOSE, 0)
	if isHttps==True:
		c.setopt(pycurl.SSL_VERIFYPEER,1)
		c.setopt(pycurl.SSL_VERIFYHOST,2)
		c.setopt(pycurl.CAINFO, certfile)

	c.setopt(c.WRITEFUNCTION ,buffer.write)
	c.setopt(c.HEADERFUNCTION,header.write)
	# setting proper method and parameters
	if method == 'get' :
		c.setopt(pycurl.HTTPGET, 1)
	elif method == 'delete' :
		c.setopt(pycurl.CUSTOMREQUEST, "DELETE")
		c.setopt(c.POSTFIELDS, str(data))
	else :
		log("[E] Unknown Http Request method found, only get or delete method are allowed!","error")

	c.perform()
	# getting response
	response = buffer.getvalue()
	headerResponse = header.getvalue()
	response_code=0
	response_code=str(c.getinfo(pycurl.RESPONSE_CODE))
	response_code=int(response_code)
	buffer.close()
	header.close()
	c.close()
	if isDebug ==True or (response_code!=200 and response_code!=204):
		print 'Request URL = ' + str(url)
		print 'Response    = ' + str(headerResponse)
	return response_code

def validateArgs(argv):
	if(len(argv)<7):
		log("[E] insufficient number of arguments. Found " + len(argv) + "; expected at least 7","error")
		printUsage()
	if not "-users" in argv :
		log("[E] -users switch was missing!","error")
		printUsage()
	if not "-admin" in argv:
		log("[E] -admin switch was missing!","error")
		printUsage()
	if not "-url" in argv:
		log("[E] -url switch was missing!","error")
		printUsage()
	if "-url" in argv:
		try:
			host=str(argv[argv.index("-url")+1])
			host=host.strip()
			if host =="" or host is None or isPairedSwitch(host):
				log("[E] invalid Ambari Admin host URL","error")
				printUsage()
			if host.lower().startswith("https"):
				if not "-sslCertPath" in argv:
					log("[E] -sslCertPath switch was missing!","error")
					printUsage()
		except IndexError:
			log("[E] missing/invalid Ambari Admin host URL","error")
			printUsage()



def main(argv):
	FORMAT = '%(asctime)-15s %(message)s'
	logging.basicConfig(format=FORMAT, level=logging.DEBUG)
	inputPath=""
	certfile=""
	tail=""
	password=""
	isHttps=False
	isUser=False
	isGroup=False
	isDebug=False
	if "-usage" in argv or "-help" in argv:
		printUsage()
	validateArgs(argv)
	for i in range(1, len(argv)) :
		if str(argv[i])== "-users" :
			restpath= "/api/v1/users"
			try:
				inputPath=str(argv[i+1])
				inputPath=inputPath.strip()
				if inputPath =="" or not os.path.exists(inputPath) or not os.path.isfile(inputPath) or not os.access(inputPath, os.R_OK) or isPairedSwitch(inputPath):
					log("[E] File '"+inputPath+"' does not exist or could not be read","error")
					sys.exit(1)
				else:
					isUser=True
				if os.stat(inputPath).st_size == 0:
					log("[E] File '"+inputPath+"' is empty!","error")
					sys.exit(1)
			except IndexError:
				log("[E] missing filename after '-users' argument","error")
				sys.exit(1)
			continue

		if str(argv[i])=="-admin" :
			try:
				user=str(argv[i+1])
				if user =="" or user is None or isPairedSwitch(user):
					log("[E] missing/invalid Ambari Admin login ID for argument '-admin'","error")
					sys.exit(1)
				continue
			except IndexError:
				log("[E] missing/invalid Ambari Admin login ID for argument '-admin'","error")
				sys.exit(1)

		if str(argv[i])=="-url" :
			try:
				host=str(argv[i+1])
				host=host.strip()
				if host =="" or host is None or isPairedSwitch(host):
					log("[E] invalid Ambari Admin host URL","error")
					sys.exit(1)
				if host.lower().startswith("https"):
					isHttps=True
				continue
			except IndexError:
				log("[E] missing/invalid Ranger Admin host URL","error")
				sys.exit(1)

		if str(argv[i])=="-debug" :
			isDebug=True
			continue

		if isHttps == True and str(argv[i])== "-sslCertPath" :
			try:
				certfile=str(argv[i+1])
				certfile=certfile.strip()
				if certfile =="" or not os.path.exists(certfile) or not os.path.isfile(certfile) or not os.access(certfile, os.R_OK) or isPairedSwitch(certfile):
					log("[E] Certificate File '"+certfile+"' does not exist or could not be read","error")
					sys.exit(1)
			except IndexError:
				log("[E] missing/invalid SSL certificate path for argument '-sslCertPath'","error")
				sys.exit(1)
			continue
	if password =="" :
		password=getpass.getpass("Enter Ambari Admin password : ")

	usernamepassword=user+":"+password
	url=host+'/api/v1/users/'+user
	response_code=0
	try:
		response_code=processRequest(url,usernamepassword,None,'get',isHttps,certfile,False)
	except pycurl.error, e:
		print e
		sys.exit(1)
	if response_code == 302 or response_code==401 or response_code==403:
		log("[E] Authentication Error:Please try with valid credentials!","error")
		sys.exit(1)
	if response_code != 200:
		log("[E] Failed to contact Ambari Admin with given parameters. Please review the parameters","error")
		printUsage()
		sys.exit(1)
	f=open(inputPath,'r')
	processedRows=0

	for line in f:
		line=line.strip()
		if line == "" or line is None:
			continue
		if isUser==True and line==user:
			log("[I] Skipping deletion of user : "+line+", Self account deletion is restricted!","info")
			continue
		url=host+'/api/v1/users/'+line+tail
		method='delete'
		data=None
		response_code=processRequest(url,usernamepassword,data,method,isHttps,certfile,isDebug)
		if response_code==302 or response_code==401:
			if isUser==True:
				log("[E] failed while deleting user '" + line + "'. Please verify the parameters","error")
			buffer.close()
			header.close()
			break
		elif response_code==200:
			if isUser==True:
				log("[I] Deleted user : "+line,"info")
			processedRows=processedRows+1
		elif response_code==404:
			if isUser==True:
				log("[E] failed while deleting user '" + line + "'. Please verify the parameters","error")
		elif response_code==400:
			if isUser==True:
				log("[I] User not found : "+line,"info")
	f.close()
	if processedRows==0:
		if isUser==True:
			log("[I] No valid user found to delete!","info")
	else:
		if isUser==True:
			log("[I] Number of user deleted : "+str(processedRows),"info")
main(sys.argv)
