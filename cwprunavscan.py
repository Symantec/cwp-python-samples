#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate AV scan execution on an AWS/Azure Instance
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Usage:  python cwprunavscan.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -instanceId=<instanceid on which you want to run AV scan> or -filename=<filename in which you have stored instance id, it should be present on current location where you are running this script>
#E.g.  python cwprunavscan.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -instanceId=i-0e1268226b99bf24c 
#OR
#python cwprunavscan.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -filename=abc.txt 
####################################################################################################################################

import os
import requests
import json
import platform
import string
import time
import sys
import argparse

if __name__=="__main__":
   
	parser = argparse.ArgumentParser(description='Get and create the CWP Connections.')
	parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
	parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
	parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
	parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
	parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
	parser.add_argument('-instanceId', required=False, metavar='instanceId', help='instanceid on which you want to run AV scan')
	parser.add_argument('-filename', required=False, metavar='filename', help='Name of file in which you have added instanceId')
	
	args = parser.parse_args()
	if args.instanceId is None and args.filename is None:
		parser.error("at least one of parameter -instanceId or -filename is required")
		
	serverURL=args.serverUrl
	customerID=args.customerId
	domainID=args.domainId
	clientID=args.clientId
	clientsecret=args.clientSecret
	if args.instanceId is None:
		filename = args.filename
		in_file = open(filename, "rt")
		instanceID = in_file.read()
		in_file.close()
	else:
		instanceID = args.instanceId
	
	print("Arguments are : \nCWP Server Url:" +serverURL+"\nCustomer Id:"+customerID+"\nDomain Id:"+domainID+"\nClient Id:"+clientID+"\nClient Secret:"+clientsecret+"\ninstance ID :"+instanceID)
	getTokenUrl = '/dcs-service/dcscloud/v1/oauth/tokens'
	putavscanUrl = '/dcs-service/dcscloud/v1/agents/av/scan'
	
	#Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
	payload = {'client_id' : clientID, 'client_secret' : clientsecret}
	header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
	response = requests.post(serverURL+getTokenUrl, data=json.dumps(payload), headers=header)
	authresult=response.status_code
	token=response.json()
	if (authresult!=200) :
		print "\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n"
		print ("\nAPI Return code is: "+str(authresult))
		exit()
	else:
		print "\nCWP API authentication successful"
		
	#Extracting auth token
	accesstoken= token['access_token']
	accesstoken = "Bearer " + accesstoken
	headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
	avscanpayload = {"instanceIds":[instanceID],"recurringJobDetails":{"recurringJobType":"MANUAL"}}
	print "\nAV Scan Payload: " + str(avscanpayload)
	avscanresponse = requests.post(serverURL+putavscanUrl, data=json.dumps(avscanpayload), headers=headerforapi)
	avscanresult=avscanresponse.status_code
	print "\nRun AV Scan API return code: " + str(avscanresult)
	if (avscanresult!=200) :
		print "\nCWP AVScan API Failed"
		exit()
	else:
		print "\nCWP AVScan API successful"