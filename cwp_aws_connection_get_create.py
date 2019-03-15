#!/usr/bin/env python
# 
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate list down AWS connections and also can create AWS connection in CWP.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_get_create.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS"
#######################################################################################################################################################################

import platform
import os
import requests
import string
import json
import time
import sys
import argparse
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
clientsecret=''
clientID=''
customerID=''
domainID=''

#Function to call CWP REST API to list down all available for particular customer
def getconnection():
  token = {}
  mydict = {}

  #CWP REST API endpoint URL for auth function
  urlmain = serverURL+"/dcs-service/dcscloud/v1"
  url = serverURL+"/dcs-service/dcscloud/v1/oauth/tokens"

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
  #CWP REST API URL for listing down all available connections
  urltogetconn = urlmain + '/cpif/cloud_connections'
  headertocheckconn = {"Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID , "Content-Type": "application/json"}
  response = requests.get(urltogetconn,  headers=headertocheckconn)
  if response.status_code != 200:
        print ("\nGet adapter configuration API failed with status code: "+str(response.status_code))
        exit()
  print ("\nGet adapter configuration API suscessful with status code: "+str(response.status_code))
  output = {}
  output = response.json()
  #print output
  print ("\n List of available connections \n")
  print (output)

def createconnection():
  token = {}
  mydict = {}
  #CWP REST API endpoint URL for auth function
  url = serverURL+"/dcs-service/dcscloud/v1/oauth/tokens"
  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
    exit()
  print ("\nCreating connection \n")
  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  createurl = serverURL+"/dcs-service/dcscloud/v1/cpif/cloud_connections"
  createheader = {"Authorization": accesstoken ,"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  header1 = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  createresponse = requests.post(createurl, data='', headers=header1)
  createConnresult=createresponse.status_code
  if (createresponse.status_code!=200) :
    print ("\nCreate adapter configuration API failed with status code: "+str(createresponse.status_code))
    print ("\nError message is: "+createresponse.text)
    exit()
  mydict = createresponse.json()
  print ("Cloud Connection is successfully configured. "+str(createresponse.status_code))
  print (mydict)
  print ("\n External ID : " + mydict[u'external_id'])
  print ("\n Connection ID : " + mydict[u'id'])
  print ("\nUse above information to update connection by running script cwp_aws_connection_update.py \n")

if __name__=="__main__":
   parser = argparse.ArgumentParser(description='Get and create the CWP Connections.')

   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   parser.add_argument('-platform', required=False, metavar='platform',default='AWS', help='Cloud Platform [AWS|Azure|GCP]')
   args = parser.parse_args()
   customerID=args.customerId
   domainID=args.domainId
   clientID=args.clientId
   clientsecret=args.clientSecret
   clould_platform = args.platform
   serverURL=args.serverUrl
   getconnection()
   createconnection()
