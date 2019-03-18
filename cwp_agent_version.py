#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to find out available agent version for all/particular OS on CWP portal under download section
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Usage: python cwp_agent_version.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key>" -platform=<All or particular platform like rhel6,rhel7 etc as mentioned in below script>
#e.g: python cwp_agent_version.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -platform=All
#######################################################################################################################################################################

import platform
import os
import requests
import string
import json
import time
import sys
import argparse

#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab. Customer need to pass which agent version he/she wants to know/get
clientsecret=''
clientID=''
customerID=''
domainID=''
platform=''

#Function to call CWP REST API to get agent version on CWP portal
def getagentversion(serverUrl,platform):
  token = {}
  mydict = {}

  #CWP REST API endpoint URL for auth function
  url = serverUrl+'/dcs-service/dcscloud/v1/oauth/tokens'

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header) 
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
    exit()

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken


  if (platform == 'all') :
    urlagentversion = serverUrl + '/dcs-service/dcscloud/v1/agents/packages/platform/all'
  else :
   urlagentversion =  serverUrl + '/dcs-service/dcscloud/v1/agents/packages/latestversion/platform/'
   urlagentversion = urlagentversion + platform
  headeragentversion= {"Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID , "Content-Type": "application/json"}

  response = requests.get(urlagentversion, headers=headeragentversion)
  if response.status_code != 200:
        print ("Get agent version API call failed \n")
        exit()
  elif response.status_code == 200:
  		print ("Get agent version call API call is successful \n")
  outputplatformcheck = {}
  outputplatformcheck = response.json()
  print (outputplatformcheck)

if __name__=="__main__":

   parser = argparse.ArgumentParser(description='Get Agent versions for specified platform')

   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   parser.add_argument('-platform', required=True, metavar='platform', help='Platform can be anything like All, centos6, centos7, rhel6, rhel7, ubuntu14, ubuntu16, amazonlinux, windows, oel7, oel6 etc')
   
   args = parser.parse_args()
   customerID=args.customerId
   domainID=args.domainId
   clientID=args.clientId
   clientsecret=args.clientSecret
   serverURL=args.serverUrl
   platform=args.platform
   platform = platform.lower()
   agentversionlist = ['all', 'centos6', 'centos7', 'rhel6', 'rhel7', 'ubuntu14', 'ubuntu16', 'amazonlinux', 'windows', 'oel7', 'oel6']
   if platform  not in  agentversionlist:
    print ("\n Invalid Platform choice . Choice should be all/rhel6/rhel7/centos6/centos7/oel6/oel7/ubuntu14/ubuntu16/amazonlinux/windows\n")
    exit()
   
   getagentversion(serverURL,platform) 
