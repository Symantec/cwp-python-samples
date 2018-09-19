#!/usr/bin/env python
# 
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate updation of created connection with arn
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_update.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> "
#To update existing connection, user will have to update updateconn.ini with external ID, Connection ID, Sync optiopn (polling true for polling or false for CloudTrail),
# Role ARN, SQS URL and SQS queue name and polling interval.
#E.g.
#clould_platform=AWS
#name=AWS Demo
#external_id=AO8xUWGe
#id=iTT4-3gLQWCCMeWzwA
#pollingIntervalHours=0
#pollingIntervalMinutes=15
#cross_account_role_arn=arn:aws:iam::782560330:role/CWPConnectionStack-role
#requires_polling=true
#sqs_queue_name=SCWPSQSQueue1
#sqs_queue_url=https://sqs.us-west-2.amazonaws.com/143926267875/SCWPSQSQueue1
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

#Function to call CWP REST API to update created/exisiting connection with arn
def updateconnection():
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
  #CWP REST API URL to update connection
  urlupdateonn = urlmain + '/cpif/cloud_connections'
  headertocheckconn = {"Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID , "Content-Type": "application/json"}
  my_dict = {}
  #Reading payload from  updateconn.ini file
  with open("updateconn.ini", 'r') as f:
    for line in f:
      items = line.split('=')
      key, values = items[0], items[1]
      my_dict[key] = values.rstrip()
  #print (my_dict)

  clould_platform = my_dict['clould_platform']
  connection_name = my_dict['name']
  external_id = my_dict['external_id']
  id1= my_dict['id']
  pollingIntervalHours = my_dict['pollingIntervalHours']
  pollingIntervalMinutes = my_dict['pollingIntervalMinutes']
  cross_account_role_arn = my_dict['cross_account_role_arn']
  requires_polling = my_dict['requires_polling']
  f.close()
  payload={}
  payload['cloud_platform'] = clould_platform
  payload['name'] = connection_name
  payload['external_id'] = external_id
  payload['id']=id1
  payload['pollingIntervalHours'] = pollingIntervalHours
  payload['pollingIntervalMinutes'] = pollingIntervalMinutes
  payload['cross_account_role_arn'] = cross_account_role_arn
  payload['requires_polling'] = requires_polling
  
  print(requires_polling)
  if requires_polling == 'true': 
        #print("Polling")
        payload['events_url'] = []
  else:
        #print("CloudTrail")
        sqs_queue_name = my_dict['sqs_queue_name']
        sqs_queue_url = my_dict['sqs_queue_url']
        payload['events_url'] = [{'name': sqs_queue_name, 'url': sqs_queue_url}]

  print ("Payload: " + str(payload) + "\n\n")
  try:
        response = requests.put(urlupdateonn, data= json.dumps(payload), headers=headertocheckconn)
        response.raise_for_status()
        print ("Successfully updated the connection.\n")
  except requests.exceptions.RequestException as err:
    print ("Error Message:", err.response.json())
  except requests.exceptions.HTTPError as errh:
    print ("Http Error Message:", errh.response.json())
  except requests.exceptions.ConnectionError as errc:
    print ("Error Connecting:", errc)
  except requests.exceptions.Timeout as errt:
    print ("Timeout Error:", errt)  


if __name__=="__main__":

   if (len(sys.argv) < 5):
      print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Usage: python cwp_aws_connection_update.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>")
      exit()

   customerID=sys.argv[1]
   domainID=sys.argv[2]
   clientID=sys.argv[3]
   clientsecret=sys.argv[4]
   updateconnection()
