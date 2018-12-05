#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to get a list of the potential threats and vulnerabilities that may impact your instances.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Usage:  python cwptandv.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -threatORvulnerability=<threats/vulnerabilities> -instanceId=<instanceid on which you want to run AV scan> 
#E.g.  python cwptandv.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -threatORvulnerability=threats -instanceId=i-0e1268226b99bf24c 
#OR
#python cwptandv.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -threatORvulnerability=vulnerabilities -instanceId=i-0e1268226b99bf24c 
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
	parser.add_argument('-instanceId', required=True, metavar='instanceId', help='instanceid for which you want to check threats or vulnerabilities')
	parser.add_argument('-threatsORvulnerabilities', required=True, metavar='threatsORvulnerabilities', help='What you want to check, threats or vulnerabilities')
	args = parser.parse_args()
		   
	serverURL=args.serverUrl
	customerID=args.customerId
	domainID=args.domainId
	clientID=args.clientId
	clientsecret=args.clientSecret
	instanceID=args.instanceId
	
	getTokenUrl = '/dcs-service/dcscloud/v1/oauth/tokens'
	getthreatUrl = '/dcs-service/dcscloud/v1/threats'
	getvulUrl = '/dcs-service/dcscloud/v1/vulnerabilities'
	
	# Set API URL depending upon the input param
	if args.threatsORvulnerabilities == "threats" :
		gettandvUrl = getthreatUrl
	elif args.threatsORvulnerabilities == "vulnerabilities" :
		gettandvUrl = getvulUrl
	else :
		print ("\nPlease provide valid input parameters use option threats/vulnerabilities\n")
		sys.exit()
	
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
		print "\nCWP API authentication successfull"

	#Extracting auth token
	accesstoken= token['access_token']
	accesstoken = "Bearer " + accesstoken

	headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
	apipayload= {"instances" : [instanceID] }
	apipayload=json.dumps(apipayload)
	
	print ("apipayload  " +  apipayload)
	
	#Get threats and vulnerabilities details using filters provided in filters.json file. If this file not found or empty API will fetch all threas or vulnerabilities.
	gettnvResponse = requests.post(serverURL+gettandvUrl, apipayload, headers=headerforapi)
	print(str(gettnvResponse))
	tnvresponseJson = gettnvResponse.json()
	tnvresult = gettnvResponse.status_code

	if (tnvresult!=200) :
		print ("\nGet CWP threats and vulnerabilities API failed with error Code:" + str(tnvresult) + "\n")
		sys.exit()
	else:
		print ("\nCWP Threats and Vulnerability API worked. Now printing API output")

	if args.threatsORvulnerabilities == "threats" :
		for item in range (0, len(tnvresponseJson.get("threatList"))):
			print ("----------------------------------------------------------")
			title = tnvresponseJson.get("threatList")[item].get("title")
			print("\nTitle :" + title)
			if(tnvresponseJson.get("threatList")[item].get("description") is not None):
				desc = tnvresponseJson.get("threatList")[item].get("description")
				print("Description :" + str(desc.encode('utf-8')))
			if(tnvresponseJson.get("threatList")[item].get("severity_level") is not None):
				severity = tnvresponseJson.get("threatList")[item].get("severity_level")
				print("Severity Level :" + severity)
			if(tnvresponseJson.get("threatList")[item].get("instances") is not None):
				instancelist = tnvresponseJson.get("threatList")[item].get("instances")
				print("Affected Instance List :" + str(instancelist))
			if(tnvresponseJson.get("threatList")[item].get("applications") is not None):
				applications = tnvresponseJson.get("threatList")[item].get("applications")
				print("Affected applications :" + str(applications))
			if(tnvresponseJson.get("threatList")[item].get("vulnerabilities") is not None):
				vulnerabilities = tnvresponseJson.get("threatList")[item].get("applications")
				print("Associated vulnerabilities :" + str(vulnerabilities))

	if args.threatsORvulnerabilities == "vulnerabilities" :
		for item in range (0, len(tnvresponseJson.get("vulnerabilities"))):
			print ("----------------------------------------------------------")
			title = tnvresponseJson.get("vulnerabilities")[item].get("title")
			print("\nTitle :" + title)
			if(tnvresponseJson.get("vulnerabilities")[item].get("description") is not None):
				desc = tnvresponseJson.get("vulnerabilities")[item].get("description")
				print("Description :" + str(desc.encode('utf-8')))
			if(tnvresponseJson.get("vulnerabilities")[item].get("cves") is not None):
				cves = tnvresponseJson.get("vulnerabilities")[item].get("cves")
				print("CVES :" + str(cves))
			if(tnvresponseJson.get("vulnerabilities")[item].get("severity_level") is not None):
				severity = tnvresponseJson.get("vulnerabilities")[item].get("severity_level")
				print("Severity Level :" + severity)
			if(tnvresponseJson.get("vulnerabilities")[item].get("instances") is not None):
				instancelist = tnvresponseJson.get("vulnerabilities")[item].get("instances")
				print("Affected Instance List :" + str(instancelist))
			if(tnvresponseJson.get("vulnerabilities")[item].get("applications") is not None):
				applications = tnvresponseJson.get("vulnerabilities")[item].get("applications")
				print("Affected Applications :" + str(applications))
			if(tnvresponseJson.get("vulnerabilities")[item].get("threats") is not None):
				threats = tnvresponseJson.get("vulnerabilities")[item].get("threats")
				print("Associated Threats :" + str(threats))
