#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to automate AV scan execution on an AW/AzureS Instance
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#####################################################################################################

import os
import requests
import json

if __name__=="__main__":
  #First get instance ID
  #metadata = os.popen('curl -s http://169.254.169.254/latest/dynamic/instance-identity/document').read()
  instanceid = os.popen('curl -s curl http://169.254.169.254/latest/meta-data/instance-id').read()
  print "\nInstance ID: " + instanceid

  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  #TODO: Make sure you save your own CWP API keys here
  clientsecret='t6r4m————————srjhc5q'
  clientID='O2ID—————————————i0qsrc3k4p69'
  customerID='SEJ——————8STA8YCxAg'
  domainID='Dqdf—————IITB2w'

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print "\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n"
    exit()
  else:
    print "\nCWP API authentication successfull"

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  #print "\nAccess Token: " + accesstoken

  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  #print "\nHeaders for AV Scan API: " + str(headerforapi)

  avscanUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/agents/av/scan'
  print "\nAV Scan  url: " + avscanUrl
  avscanpayload = {"instanceIds":[instanceid],"recurringJobDetails":{"recurringJobType":"MANUAL"}}
  print "\nAV Scan Payload: " + str(avscanpayload)
  avscanresponse = requests.post(avscanUrl, data=json.dumps(avscanpayload), headers=headerforapi)
  avscanresult=avscanresponse.status_code
  print "\nRun AV Scan API return code: " + str(avscanresult)
  if (avscanresult!=200) :
    print "\nCWP AVScan API Failed"
    exit()
  else:
    print "\nCWP AVScan API successfull" 




