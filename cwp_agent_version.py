#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to find out available agent version for all/particular OS on CWP portal under download section
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key and os (all/partilucar , e.g all/centos6/rhel7/amzonlinux, etc) as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_agent_version.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <platform>"
#######################################################################################################################################################################

import platform
import os
import requests
import string
import json
import time
import sys

#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab. Customer need to pass which agent version he/she wants to know/get
clientsecret=''
clientID=''
customerID=''
domainID=''
platform=''

#Function to call CWP REST API to get agent version on CWP portal
def getagentversion(platform):
  token = {}
  mydict = {}

  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

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
    urlagentversion = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/agents/packages/platform/all'
  else :
   urlagentversion =  'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/agents/packages/latestversion/platform/'
   urlagentversion = urlagentversion + platform
  headeragentversion= {"Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID , "Content-Type": "application/json"}

  response = requests.get(urlagentversion, headers=headeragentversion)
  if response.status_code != 200:
        print ("Get agent version  API call failed \n")
        exit()
  outputplatformcheck = {}
  outputplatformcheck = response.json()
  print (outputplatformcheck)

if __name__=="__main__":

   if (len(sys.argv) < 6):
      print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab and choice of platform. Usage: python cwp_agent_version.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <platform>")
      exit()

   customerID=sys.argv[1]
   domainID=sys.argv[2]
   clientID=sys.argv[3]
   clientsecret=sys.argv[4]
   platform=sys.argv[5]
   platform = platform.lower()
   agentversionlist = ['all', 'centos6', 'centos7', 'rhel6', 'rhel7', 'ubuntu14', 'ubuntu16', 'amazonlinux', 'windows', 'oel7', 'oel6']
   if platform  not in  agentversionlist:
    print ("\n Invalid Platform choice . Choice should be all/rhel6/rhel7/centos6/centos7/oel6/oel7/ubuntu14/ubuntu16/amazonlinux/windows\n")
    exit()
   
   getagentversion(platform)

