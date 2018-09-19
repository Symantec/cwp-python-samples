#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate list down AWS connection availabe for the customer and also can create connection for customer.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <clould_platform> <connection_name> <external_id> <cross_account_role_arn> <syncIntervalHours> <syncIntervalMinutes> [ <requires_polling=true>] [<requires_polling=false> <sqs_queue_name> <sqs_queue_url>]
#E.g.
#E.g. 
############################################################################################################################################################################################################################################################################################################

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

  payload={}
  payload['cloud_platform'] = clould_platform
  payload['name'] = connection_name
  payload['external_id'] = external_id
  payload['cross_account_role_arn'] = cross_account_role_arn
  payload['pollingIntervalHours'] = syncIntervalHours
  payload['pollingIntervalMinutes'] = syncIntervalMinutes
  print(requires_polling)
  
  if requires_polling == 'requires_polling=true':
        #print("Polling")
        payload['requires_polling'] = 'true'
        payload['events_url'] = []
  else:
        #print("CloudTrail")
        payload['requires_polling'] = 'false'
        payload['events_url'] = [{'name': sqs_queue_name, 'url': sqs_queue_url}]

  print ("Payload: " + str(payload) + "\n\n")

  createresponse = requests.post(createurl, data=json.dumps(payload), headers=header1)
  mydict = createresponse.json()
  print (mydict)
  print ("\nConnection ID : " + mydict[u'id'])
  print ("\nUse above Connection ID for any future Connection Update API calls.\n")

if __name__=="__main__":
   if (len(sys.argv) < 11):
      print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Usage: python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> and cloud platform, connection name, cross account role ARN and polling options parameters")
      exit()

   customerID=sys.argv[1]
   domainID=sys.argv[2]
   clientID=sys.argv[3]
   clientsecret=sys.argv[4]
   clould_platform = sys.argv[5]
   connection_name = sys.argv[6]
   external_id = sys.argv[7]
   cross_account_role_arn = sys.argv[8]
   syncIntervalHours = sys.argv[9]
   syncIntervalMinutes = sys.argv[10]
   requires_polling = sys.argv[11]
   if (requires_polling == 'requires_polling=false'):
     if (len(sys.argv) < 13):
        print ("You have specified CloudTrail Sync option but missed passing SQS Queue Name and SQS Queue URL")
        exit()
     sqs_queue_name = sys.argv[12]
     sqs_queue_url = sys.argv[13]
   
   getconnection()
   createconnection()
   
