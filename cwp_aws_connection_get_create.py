#!/usr/bin/env python
# 
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate list down AWS connection availabe for the customer and also can create connection for customer.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>"
#######################################################################################################################################################################

import platform
import os
import requests
import string
import json
import time
import sys
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
  urlmain = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1'
  url = urlmain + '/oauth/tokens'

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
        print ("Get Connection API call failed \n")
        exit()
  output = {}
  output = response.json()
  #print output
  print ("\n List of available connections \n")
  print (output)

def createconnection():
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
  print ("\nCreating connection \n")
  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  createurl = "https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/cpif/cloud_connections"
  createheader = {"Authorization": accesstoken ,"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  header1 = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  createresponse = requests.post(createurl, data='', headers=header1)
  mydict = createresponse.json()
  print (mydict)
  print ("\n External_ID : " + mydict[u'external_id'])
  print ("\n Connection ID : " + mydict[u'id'])
  print ("\nUse above information to update connection by running script cwp_aws_connection_update.py \n")

if __name__=="__main__":
   if (len(sys.argv) < 5):
      print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Usage: python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>")
      exit()

   customerID=sys.argv[1]
   domainID=sys.argv[2]
   clientID=sys.argv[3]
   clientsecret=sys.argv[4]
   getconnection()
   createconnection()
