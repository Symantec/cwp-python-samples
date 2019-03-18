#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Sample Python Script to enumerate CWP assets and run on demand AC scan on these assets. 
#The assets get call is filtered by OS Platform type (Windows/Unix) and optional asset tag name and value set in Azure/AWS or in CWP Console
#This script gets all instances from Azure. If you want to get Instances from AWS, change query filter to (cloud_platform in [\'AWS\'])
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service and https://apidocs.symantec.com/home/scwp#_anti_malware_scan_service
#Pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_runavscan_onselectassets.py  -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -os=<Windows/Linux> -platform=<AWS/Azure> -tagName=<tagname> -tagValue=<tagvalue>"
#E.g.  python cwp_runavscan_onselectassets.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -os=Windows -platform=AWS -tagName=name -tagValue=ABCDEFG
#OR
#python cwp_runavscan_onselectassets.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -os=Unix -platform=AWS 
##########################################################################################################################################################################

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
	parser.add_argument('-platform', required=True, metavar='platform', help='Cloud platform of selected machine, on which you want to run AV scan')
	parser.add_argument('-os', required=False, metavar='os', help='Operating System of instances on which you want to run AV scan')
	parser.add_argument('-tagName', required=False, metavar='tagName', help='Name of tag you want to specify for filter')
	parser.add_argument('-tagValue', required=False, metavar='tagValue', help='Value of selected tag')
		   
	args = parser.parse_args()
	if args.tagName is not None:
		tagName=args.tagName
		if args.tagValue is None:
			parser.error("Enter tag details for tag - " + tagName)
		else:
			tagValue=args.tagValue
	else:
		tagName=""
		tagValue=""
			
			
	serverURL=args.serverUrl
	customerID=args.customerId
	domainID=args.domainId
	clientID=args.clientId
	clientsecret=args.clientSecret
	platform=args.platform
	if args.os is not None:
		os=args.os
	else:
		os=""
	
	
	#CWP REST API endpoint URL for auth function
	print("Arguments are : \nCWP Server Url:" +serverURL+"\nCustomer Id:"+customerID+"\nDomain Id:"+domainID+"\nClient Id:"+clientID+"\nClient Secret:"+clientsecret+"\nOS :"+os+"\nCloud Platform :"+platform+"\nTag Name :"+tagName+ "\nTag Value :"+tagValue)
	getTokenUrl = '/dcs-service/dcscloud/v1/oauth/tokens'
	getInstanceIdUrl = '/dcs-service/dcscloud/v1/ui/assets'
	avscanUrl='/dcs-service/dcscloud/v1/agents/av/scan'
	
	#Get 10 records in each page
	defaultpagesize = 10
	targetinstanceid = ""
	
	#Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
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
	
	#Where clause to filter results.
	#Only select instances from Azure and those with agent installed and are in running state.
	whereclause= "(cloud_platform in ['"+platform+"'])&(instance_state in ['Running'])&(agent_installed='Installed')&(included_installed_products.status.AMD='Online')"
	if (os != "") :
		whereclause= whereclause + "&(platform='" + os + "')"
		
	#Now if tagName and/or tagvalue was passed add that to the were clause
	if (tagName != ""):
		whereclause= whereclause + "&(included_dcs_tags.name='" + tagName +"')"
	if (tagValue != ""):
		whereclause= whereclause + "&(included_dcs_tags.value='" + tagvalue +"')"
		
	#Payload for getting one page at a time, 10 records in a page. Offset tells which record from the result set to start getting. 
	#Offset tells you home many records to skip. Limit is number of items to get starting from Offset.
	#Setup the request paramerer json object with default values
	getScwpAssetsRequest = {'limit':0,'offset':0, 'where':'', 'include':'installed_products'}
	
	pageNumber = 0
	getScwpAssetsRequest['where'] = whereclause
	while True:
		getScwpAssetsRequest['offset'] = pageNumber * defaultpagesize
		getScwpAssetsRequest['limit'] = defaultpagesize
		print ("Current Page Number: " + str(pageNumber))
		pageNumber += 1
		print("Request Parameters: " + json.dumps(getScwpAssetsRequest))
		getInstanceIdResponse = requests.post(serverURL+getInstanceIdUrl, data=json.dumps(getScwpAssetsRequest), headers=headerforapi)
		#print (getInstanceIdResponse)
		assetresponseJson = getInstanceIdResponse.json()
		#print (assetresponseJson)
		scwpAssets = assetresponseJson['results']
		assetresult=getInstanceIdResponse.status_code
		if (assetresult!=200) :
			print ("\nGet CWP Asset API failed with error Code:" + str(assetresult) + "\n")
			exit()
		else:
			print ("\nCWP Asset API worked. Now printing API output")
		if (not scwpAssets):
			print("No Assets in current Page. Exiting..")
			print ("*********************************************************")
			exit()
			#break
		
		print ("Assets in Page: " + str(len(scwpAssets)))
		
		for scwpAssset in scwpAssets:
			#Run on demand scan only if AMD service is running on the instance
			runondemandscan='true'
			#print ('\nAsset Info Json:\n' + str(scwpAssset))
			print ("----------------------------------------------------------")
			#Save instance ID to be passed to AV Scan API
			instanceid = scwpAssset.get("instance_id")
			name = scwpAssset.get("name")
			connectionInfo = scwpAssset.get("connectionInfo")
			security_agent = scwpAssset.get("security_agent")
			print ("Instance ID: " + str(instanceid) + "\n")
			print ("Instance name: " + str(name) + "\n")
			if (connectionInfo is not None) :
				print ("Instance Connection Name: " + str(connectionInfo["name"]) + "\n")
				#print ("Connection Info JSON Object: " + str(connectionInfo))
			else:
				print ("Instance is private with no connection" + "\n")
					
			#Print Agent version info and AV Definitions Info
			if security_agent is not None:
				props = security_agent.get("props")
				#print ("Security Agent: " + str(props))
				if props is not None:
					if props.get("cwp_agent_product_version") is not None:
						print ("Instance Hardening Agent Version: " + str(props.get("cwp_agent_product_version")))
						if props.get("cwp_av_agent_product_version") is not None:
							print ("Instance AntiVirus Agent Version: " + str(props.get("cwp_av_agent_product_version")))
				contents = security_agent.get("contents")
				if contents is not None:
					if contents.get("antivirus:version") is not None:
						print ("Instance Virus Definition Version: " + str(contents.get("antivirus:version")))

				#Print Supported Agent Technologies and see if Antimalware (AMD) service is present
				if (security_agent.get("supported_technologies")) is not None:
					#Set run scan false and only turn it to true if AMD service is available on the instance
					runondemandscan = 'false'
					print ("\nAgent Current Supported Protection Technologies: " +  str(security_agent.get("supported_technologies")))
					for scwpTech in security_agent.get("supported_technologies"):
						if scwpTech == 'AMD':
							print ("AMD Service available on Instance: " + str(instanceid))
							runondemandscan = 'true'
							
			#Dump the entire CWP security agent JSON
			#print ("\nPrinting Entire Security Agent Object Json: " + str(security_agent))
			else:
				runondemandscan = 'false'

			#Print tags - CWP or AWS/Azure
			if (scwpAssset.get("included_dcs_tags")is not None):
				instance_tags = scwpAssset.get("included_dcs_tags")
				#print ("\nPrinting Tags Json: " + str(instance_tags))

			if (runondemandscan == 'true'):
				#print("\nAV Scan  url: " + avscanUrl)
				avscanpayload = {"instanceIds":[instanceid],"recurringJobDetails":{"recurringJobType":"MANUAL"}}
				#print ("\nAV Scan Payload: " + str(avscanpayload))
				avscanresponse = requests.post(serverURL+avscanUrl, data=json.dumps(avscanpayload), headers=headerforapi)
				avscanresult=avscanresponse.status_code
				print("\nRun AV Scan API return code: " + str(avscanresult))
				if (avscanresult!=200) :
					print ("\nCWP AV Scan API Failed on instance" +  str(instanceid)) 
				else:
					print ("\nCWP on demand AV scan successfully started on Instance: " +  str(instanceid))
			print("==============================================================================")
