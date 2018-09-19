#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate list down AWS connection availabe for the customer and also can create connection for customer.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id> -roleArn=<Role ARN> -syncIntervalHours=<Interval in Hours> -syncIntervalMinutes=<Interval in Minutes> -requires_polling=<Periodic Sync?[True|False]> -sqsQueueName=<SQS Queue Name> -sqsQueueUrl=<SQS URL Name>
#E.g. python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=False -sqsQueueName=SQSQueue-xxxxxxxxxxxx -sqsQueueUrl=https://sqs.us-east-1.amazonaws.com/xxxxxxxxxxxx/CloudTrail-xxxxxxx-SQS
#E.g. python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=True
############################################################################################################################################################################################################################################################################################################

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
  url = urlmain + "/oauth/tokens"

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
  print ("List of available connections")
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
  print ("****** Creating connection ******")
  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  createurl = serverURL+"/dcs-service/dcscloud/v1/cpif/cloud_connections"
  createheader = {"Authorization": accesstoken ,"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  header1 = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}

  payload={}
  payload['cloud_platform'] = clould_platform
  payload['name'] = connection_name
  payload['external_id'] = external_id
  payload['cross_account_role_arn'] = cross_account_role_arn
  payload['pollingIntervalHours'] = syncIntervalHours
  payload['pollingIntervalMinutes'] = syncIntervalMinutes
  
  if requires_polling == 'True':
        payload['requires_polling'] = 'true'
        payload['events_url'] = []
  else:
        payload['requires_polling'] = 'false'
        payload['events_url'] = [{'name': sqs_queue_name, 'url': sqs_queue_url}]

  print ("Payload: " + str(payload))

  createresponse = requests.post(createurl, data=json.dumps(payload), headers=header1)
  mydict = createresponse.json()
  if createresponse.status_code != 200 :
     print("Connection configuration failed with response status code  :"+str(createresponse.status_code))
     print (mydict)
     exit()
  print (mydict)
  print ("Cloud Connection is successfully configured. "+str(createresponse.status_code))
  print ("Connection ID :" + mydict["id"])
  print ("Use above Connection ID for any future Connection Update API calls.")

if __name__=="__main__":
   
   parser = argparse.ArgumentParser(description='Get and create the CWP Connections.')
   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   parser.add_argument('-platform', required=True, metavar='platform', help='Cloud Platform [AWS|Azure|GCP]')
   parser.add_argument('-connectionName', required=True, metavar='connectionName', help='Cloud connection name to be configured')
   parser.add_argument('-externalId', required=True, metavar='extenalId', help='External Id')
   parser.add_argument('-roleArn', required=True, metavar='roleArn', help='AWS Role ARN to be configured.')
   parser.add_argument('-syncIntervalHours', required=True, metavar='syncIntervalHours',type=int, help='Cloud Connection sync interval in hours')
   parser.add_argument('-syncIntervalMinutes', required=True, metavar='syncIntervalMinutes', type=int,help='Cloud Connection sync interval in Minutes')
   parser.add_argument('-requires_polling', required=True, metavar='requires_polling',default=False,  help='Requres polling [True|False]')
   parser.add_argument('-sqsQueueName',  metavar='sqsQueueName', help='AWS SQS Queue Name')
   parser.add_argument('-sqsQueueUrl' ,  metavar='sqsQueueUrl', help='AWS SQS Queue URL')
   
   args = parser.parse_args()
   if args.requires_polling == 'False':
      print("CloudTrail Sync is set")
      if args.requires_polling=='False' and args.sqsQueueName is None and args.sqsQueueUrl is None:
         parser.error("--prox requires -sqsQueueUrl and -sqsQueueName.")
      sqs_queue_name = args.sqsQueueName
      sqs_queue_url  = args.sqsQueueUrl 
   else:
      print("Periodic Sync is set")
   args = parser.parse_args()
   customerID=args.customerId
   domainID=args.domainId
   clientID=args.clientId
   clientsecret=args.clientSecret
   clould_platform = args.platform
   connection_name = args.connectionName
   external_id = args.externalId
   cross_account_role_arn = args.roleArn
   syncIntervalHours = args.syncIntervalHours
   syncIntervalMinutes = args.syncIntervalMinutes
   requires_polling = args.requires_polling
   serverURL=args.serverUrl
   
   print("Arguments are : \nCWP Server Url:" +serverURL+"\nCustomer Id:"+customerID+"\nDomain Id:"+domainID+"\nClient Id:"+clientID+"\nClient Secret:"+clientsecret+"/n Cloud Platform:"+clould_platform+"\nConnection Name:"+connection_name+"\nExternal Id:"+external_id+"\nCross Account Role ARN:"+cross_account_role_arn+"\nSync Interval in Hour:"+str(syncIntervalHours)+"\nSync Interval in Minutes:"+str(syncIntervalMinutes)+"\n")
   getconnection()
   createconnection()
   
