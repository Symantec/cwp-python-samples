#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All righ1ts reserved.
#
#Script to get CWP asset agent installation status.
#This script has been modified to only enumerate assets that have all security technologies (AMD, IPS, IDS) offline
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwpasset_agent_status.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <instanceid>"
#E.g.: python cwpasset_agent_status.py SE*****Ag Dq******w O2ID.SE*******vmuo qa*******d8 i-06***********9e
########################################################################################################################################################

import os
import requests
import json
import sys

if __name__=="__main__":

  if (len(sys.argv) < 5):
    print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Usage: python cwpasset_AgentTechStatus.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>")
    exit()
  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  defaultpagesize = 10
  targetinstanceid = ""
  agent_status = ""
  #Save CWP API keys here
  customerID=sys.argv[1]
  domainID=sys.argv[2]
  clientID=sys.argv[3]
  clientsecret=sys.argv[4]
  targetinstanceid=sys.argv[5]

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
    exit()
  #else:
    #print ("\nCWP API authentication successful")

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  #print ("\nAccess Token: " + accesstoken)

  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  #print ("\nHeaders for Asset API: " + str(headerforapi))
  
  #Get Instances in AWS account or given instance id 
  getInstanceIdUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/ui/assets'
  #whereclause= "(instance_id='" + targetinstanceid + "')&(cloud_platform in ['AWS'])&(agent_installed='Installed')&(instance_state in ['Running'])"
  whereclause= "(instance_id='" + targetinstanceid + "')"
  #print ("\nGet Asset List API call: " + getInstanceIdUrl)

  #Payload for getting one page at a time, 10 records in a page. Offset tells which record from the result set to start getting. Offet tells you home many records to skip. Limit is number of items to get starting from Offset.
  getScwpAssetsRequest = {'limit':10,'offset':0, 'where':'', 'include':'installed_products'}

  pageNumber = 0
  getScwpAssetsRequest['where'] = whereclause
  #print("Now exporting instance agent status")
  #print("==============================================================================") 
  #print ("Instance ID,  InstanceName,  InstanceConnectionName, InstanceHardeningAgentVersion,  InstanceAntiVirusAgentVersion,  InstanceVirusDefinitionVersion")
  #while True:
  getScwpAssetsRequest['offset'] = pageNumber * defaultpagesize
  getScwpAssetsRequest['limit'] = defaultpagesize
  pageNumber += 1
  getInstanceIdResponse = requests.post(getInstanceIdUrl, data=json.dumps(getScwpAssetsRequest), headers=headerforapi)
  assetresponseJson = getInstanceIdResponse.json()
  scwpAssets = assetresponseJson['results']
  #print (scwpAssets)
  if (not scwpAssets):
    print ("Instance does not have agent Installed")
    exit()

  assetresult=getInstanceIdResponse.status_code
  if (assetresult!=200) :
    print ("\nGet CWP Asset API failed with error Code:" + str(assetresult) + "\n")
    exit()

  for scwpAssset in scwpAssets:
    instanceid = scwpAssset.get("instance_id")
    if instanceid is None:
      instanceid = "Not Available"
    instancename = scwpAssset.get("name")
    if instancename is None:
      instancename = "Not Available"
    agent_status = scwpAssset.get("agent_installed")
    if agent_status is None:
      agent_status = "Not Available"
    else:
      agent_status = agent_status["display_value"]
    #print (agent_status)
      
    connectionInfo = scwpAssset.get("connectionInfo")
    security_agent = scwpAssset.get("security_agent")
    InstanceConnectionName = "Not Available"
    if (connectionInfo is not None) :
        InstanceConnectionName = str(connectionInfo["name"])
    
    #Get Agent version info and AV Definitions Info
    InstanceHardeningAgentVersion = "Not Available"
    InstanceAntiVirusAgentVersion = "Not Available"
    InstanceVirusDefinitionVersion = "Not Available"
    if security_agent is not None:
        props = security_agent.get("props")
        if props is not None:
                if props.get("cwp_agent_product_version") is not None:
                        InstanceHardeningAgentVersion = str(props.get("cwp_agent_product_version"))
                        if (scwpAssset.get("platform") == "Windows"):
                             if props.get("cwp_av_agent_product_version") is not None:
                                 InstanceAntiVirusAgentVersion = str(props.get("cwp_av_agent_product_version"))
                        else:
                             #For Linux, there is no separate AV agent
                             InstanceAntiVirusAgentVersion = "Not Applicable"
        contents = security_agent.get("contents")
        if contents is not None:                
                if contents.get("antivirus:version") is not None:
                        InstanceVirusDefinitionVersion = str(contents.get("antivirus:version"))

        
    print ("Instance ID:" + instanceid + "\n" + "InstanceName:" + instancename + "\n" + "Agent Status:" + agent_status + "\n" + "InstanceConnectionName:" + InstanceConnectionName + "\n" +"InstanceHardeningAgentVersion:" + InstanceHardeningAgentVersion + "\n" + "InstanceAntiVirusAgentVersion:" +  InstanceAntiVirusAgentVersion + "\n" + "InstanceVirusDefinitionVersion:" + InstanceVirusDefinitionVersion)

        

