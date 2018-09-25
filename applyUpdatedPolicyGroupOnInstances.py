#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to automate apply updated policy group on associated instances.
#Usage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id> -roleArn=<Role ARN> -syncIntervalHours=<Interval in Hours> -syncIntervalMinutes=<Interval in Minutes> -requires_polling=<Periodic Sync?[True|False]> -sqsQueueName=<SQS Queue Name> -sqsQueueUrl=<SQS URL Name>
#E.g. python applyUpdatedPolicyGroupOnInstances.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -policyGroupName="<Policy_Group_Name>"
############################################################################################################################################################################################################################################################################################################

import platform
import os
import requests
import string
import json
import time
import sys
import argparse
clientsecret=''
clientID=''
customerID=''
domainID=''
policyGroupId=''
cwpassets = []

getTokenUrl = '/dcs-service/dcscloud/v1/oauth/tokens'
getPolicyGroupDetailUrl = '/dcs-service/dcscloud/v1/policy/policy_groups/basic'
getAssetAssociatedWithPolicyUrl1='/dcs-service/dcscloud/v1/policy/policy_groups/'
getAssetAssociatedWithPolicyUrl2='/assets'
putAssetAssociatedWithPolicyUrl1='/dcs-service/dcscloud/v1/policy/ui/policy_groups/'
putAssetAssociatedWithPolicyUrl2='/assets'
applyPolicyGroupOnassetsUrl=''

def applyPolicyGroup():
  token = {}
  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(serverURL+getTokenUrl, data=json.dumps(payload), headers=header) 
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
    exit()
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  customerheader = {"Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID , "Content-Type": "application/json"}
  response = requests.get(serverURL+getPolicyGroupDetailUrl,  headers=customerheader)
  if response.status_code != 200:
        print ("Get policy group API call failed \n")
        exit()
  pgList = response.json()
  policyArray =pgList['results']
  pgExist=False
  for pg in policyArray:
    global policyGroupName
    if pg['name'].lower() == policyGroupName.lower():
      pgExist = True
      policyGroupName = pg['name']
      policyGroupId = pg['id']
      print("Policy Group Id for ["+policyGroupName+"] is ["+policyGroupId+"]")

  if pgExist==False:
    print ("***** Policy Group with Name "+policyGroupName+" is not present in CWP account. \nPlease verify if correct name provided.")
    exit()
  getAssetsAssociatedWithPolicyGroupUrl =   getAssetAssociatedWithPolicyUrl1+policyGroupId+getAssetAssociatedWithPolicyUrl2
  response = requests.get(serverURL+getAssetsAssociatedWithPolicyGroupUrl,  headers=customerheader)
  if response.status_code != 200:
        print ("Get assets associated with policy group API call failed with response status code  :"+str(response.status_code)+"\n")
        exit()
  assetList = response.json()
  print("Below is list of instances on which updated policy group ["+policyGroupName+"] will be applied.\nInstance Id's are")
  for asset in assetList:
    print("["+asset['instance_id']+"]")
    cwpassets.append(str(asset['instance_id']))
  print("Policy Group ["+policyGroupName+"] has ["+str(len(cwpassets))+"] instances associated.")
  choice = raw_input("Do you want to continue? (Y/N):")
  if choice.lower() == 'y' or choice.lower()=='yes':
    print("Applying policy group on instances.")
  else:
    print("Exiting.")
    exit()
  print(cwpassets)
  response = requests.put(serverURL+getAssetsAssociatedWithPolicyGroupUrl,  headers=customerheader,data=json.dumps(cwpassets))
  if response.status_code != 200:
        print ("Apply policy group API call failed with response status code  :"+str(response.status_code)+"\n")
        apiResp = response.json()
        print ("Error response is "+apiResp['errorResponse']['errorRemedy'])
        exit()
  print ("********** Succefully initiated apply policy group job on instances.************")
  print ("Navigate to Alerts & Events workspace on CWP Portal to verify job status")

if __name__=="__main__":
   
   parser = argparse.ArgumentParser(description='Get and create the CWP Connections.')

   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   parser.add_argument('-policyGroupName', required=True, metavar='policyGroupName', help='Policy group name which needed to apply')
   
   args = parser.parse_args()
   customerID=args.customerId
   domainID=args.domainId
   clientID=args.clientId
   clientsecret=args.clientSecret
   policyGroupName = args.policyGroupName
   serverURL=args.serverUrl
   
   print("Arguments are : \nCWP Server Url:" +serverURL+"\nCustomer Id:"+customerID+"\nDomain Id:"+domainID+"\nClient Id:"+clientID+"\nClient Secret:"+clientsecret+"\nPolicy Group Name :"+policyGroupName+"\n")
   applyPolicyGroup()
   
   
