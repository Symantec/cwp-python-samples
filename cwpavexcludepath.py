#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to update AV exclusion path for Windows Servers. Call this "agents/av/configs/" rest API to push to all Windows AV agents a list of one of
#more folders to skip AV Scan.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwpavexcludepath.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>"
#####################################################################################################

import os
import requests
import json
import sys

if __name__=="__main__":
  
  if (len(sys.argv) < 5):
      print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Usage: python cwpagentinstall.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>")
      exit()

  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  #CWP API keys were passed thrugh command line
  customerID=sys.argv[1]
  domainID=sys.argv[2]
  clientID=sys.argv[3]
  clientsecret=sys.argv[4]

  print ("Keys: " + customerID + " " + domainID + " " + clientID + " " + clientsecret)

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Check clientsecret, clientID, customerID, and domainID\n")
    exit()
  else:
    print ("\nCWP API authentication successfull")

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  #print "\nAccess Token: " + accesstoken

  #REST endpoint for Exclusion path
  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  exclusionURL = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/agents/av/configs/'
  print ("\nAV Exclusion path API URL: " + exclusionURL)
  avexclusionpayload = '{"scanExclusion":{"directoryExclusions":[{"directoryPath":"C:\\\\Program Files\\\\","platformType":"WINDOWS"},{"directoryPath":"C:\\\\ProgramData\\\\","platformType":"WINDOWS"}]},"platformType":"windows","enableIntrusionProtection":true}'
  print ("\nAV Exclusion Payload: " + str(avexclusionpayload))
  avexclusionresponse = requests.post(exclusionURL, data=avexclusionpayload, headers=headerforapi)
  avexclusionresult=avexclusionresponse.status_code
  print ("\nRun AV Exclusion API return code: " + str(avexclusionresult))
  if (avexclusionresult!=200) :
    print ("\nCWP AV Exclusion API Failed")
    exit()
  else:
    print ("\nCWP AV Exclusion API successfull")
