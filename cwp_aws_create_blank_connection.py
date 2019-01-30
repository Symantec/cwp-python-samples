#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate creation of a blank AWS connection in CWP using Connection creation API with a customer provided external ID.
#The API returns CWP connection ID that can be used to update the connection with Role ARN, Polling/CloudTrail settings
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id>
#E.g. python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G
#E.g. python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G
###################################################################################################################################################################################################

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
  print("Access Token is : "+str(accesstoken))
  createurl = serverURL+"/dcs-service/dcscloud/v1/cpif/cloud_connections"
  createheader = {"Authorization": accesstoken ,"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  header1 = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}

  payload={}
  payload['cloud_platform'] = clould_platform
  payload['name'] = connection_name
  payload['external_id'] = external_id
  
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
   
   parser = argparse.ArgumentParser(description='Create a blank AWS Connection in CWP.')

   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   parser.add_argument('-platform', required=True, metavar='platform', help='Cloud Platform [AWS|Azure|GCP]')
   parser.add_argument('-connectionName', required=True, metavar='connectionName', help='Cloud connection name to be configured')
   parser.add_argument('-externalId', required=True, metavar='extenalId', help='External Id')
   
   args = parser.parse_args()
   customerID=args.customerId
   domainID=args.domainId
   clientID=args.clientId
   clientsecret=args.clientSecret
   clould_platform = args.platform
   connection_name = args.connectionName
   external_id = args.externalId
   serverURL=args.serverUrl
   
   print("Arguments are : \nCWP Server Url:" +serverURL+"\nCustomer Id:"+customerID+"\nDomain Id:"+domainID+"\nClient Id:"+clientID+"\nClient Secret:"+clientsecret+"/n Cloud Platform:"+clould_platform+"\nConnection Name:"+connection_name+"\nExternal Id:"+external_id+"\n")
   createconnection()
   
