#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to get CWP asset enumeration. Get asset (instance) details, one page at a time
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwpasset.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <instanceid>"
#instanceid is optional. if instance Id is not passed, the script enumerates all instances in AWS. To get instances from Azure chage query filter to (cloud_platform in [\'Azure\'])
#Sample Usage: python cwpasset.py 'SEJHHHHHHA8YCxAg' 'DqdfTTTTTTTTTTB2w' 'O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojqsrc3k4p69' 't6r4mUUUUUUUUUg2srjhc5q' i-UUUUUUff50b85
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

  defaultpagesize = 10
  targetinstanceid = ""
  #Save CWP API keys here
  customerID=sys.argv[1]
  domainID=sys.argv[2]
  clientID=sys.argv[3]
  clientsecret=sys.argv[4]
  if (len(sys.argv) == 6):
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
  else:
    print ("\nCWP API authentication successfull")

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  #print ("\nAccess Token: " + accesstoken)

  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  #print ("\nHeaders for Asset API: " + str(headerforapi))
  
  #Get Instances in AWS account, if instance id was passed enumerate instance detail only for that instance if not for all instances
  getInstanceIdUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/ui/assets'

  #Where clause to filter results.
  if (targetinstanceid != "") :
      whereclause= "(instance_id='" + targetinstanceid + "')&(cloud_platform in ['AWS'])"
  else:
      whereclause= "(cloud_platform in ['AWS'])"
  print ("\nGet Asset List API call: " + getInstanceIdUrl)

  #Payload for getting one page at a time, 10 records in a page. Offset tells which record from the result set to start getting. Offet tells you home many records to skip. Limit is number of items to get starting from Offset.
  getScwpAssetsRequest = {'limit':10,'offset':0, 'where':'', 'include':'installed_products'}

  pageNumber = 0
  print (whereclause)
  getScwpAssetsRequest['where'] = whereclause
  while True:
      getScwpAssetsRequest['offset'] = pageNumber * defaultpagesize
      getScwpAssetsRequest['limit'] = defaultpagesize
      print ("Current Page Number: " + str(pageNumber))
      pageNumber += 1
      getInstanceIdResponse = requests.post(getInstanceIdUrl, data=json.dumps(getScwpAssetsRequest), headers=headerforapi)
      #print (getInstanceIdResponse)
      assetresponseJson = getInstanceIdResponse.json()
      #print (assetresponseJson)
      scwpAssets = assetresponseJson['results']
      if (not scwpAssets):
        break
      

      assetresult=getInstanceIdResponse.status_code
      if (assetresult!=200) :
        print ("\nGet CWP Asset API failed with error Code:" + str(assetresult) + "\n")
        exit()
      else:
        print ("\nCWP Asset API worked. Now printing API output")

      print ("----------------------------------------------------------")
      print ("Assets in Page: " + str(len(scwpAssets)))
      for scwpAssset in scwpAssets:
        #print ('\nAsset Info Json:\n' + str(scwpAssset))
        print ("----------------------------------------------------------")
        instanceid = scwpAssset.get("instance_id")
        name = scwpAssset.get("name")
        connectionInfo = scwpAssset.get("connectionInfo")
        security_agent = scwpAssset.get("security_agent")
        print ("Instance ID: " + str(instanceid) + "\n")
        print ("Instance name: " + str(name) + "\n")
        if (connectionInfo is not None) :
            print ("Instance Connection Name: " + str(connectionInfo["name"]) + "\n")
            if connectionInfo["awsAccoundID"] is not None:
                print ("Instance Connection AWS Account Number: " + str(connectionInfo["awsAccoundID"]) + "\n")
            print ("Connection Info JSON Object: " + str(connectionInfo))
        else:
            print ("Instance is private with no connection" + "\n")
        
        #Print Agent version info and AV Definitions Info
        if security_agent is not None:
            props = security_agent.get("props")
            #print ("Security Agent: " + str(props))
            if props is not None:
                    if props.get("cwp_agent_product_version") is not None:
                            print ("Instance Hardening Agent Version: " + str(props.get("cwp_agent_product_version")))
                    if props.get("cwp_av_agent_product_version") is not None:
                            print ("Instance AntiVirus Agent Version: " + str(props.get("cwp_av_agent_product_version")))
            contents = security_agent.get("contents")
            if contents is not None:                
                    if contents.get("antivirus:version") is not None:
                            print ("Instance Virus Definition Version: " + str(contents.get("antivirus:version")))

            #Print Support Agent Technologies
            if (security_agent.get("supported_technologies")) is not None:
                    print ("\nAgent Current Supported Protection Technologies: " +  str(security_agent.get("supported_technologies")))
            #Dump the entire CWP security agent JSON
            print ("\nPrinting Entire Security Agent Object Json: " + str(security_agent))

        #Print tags - CWP or AWS/Azure
        if (scwpAssset.get("included_dcs_tags")is not None):
            instance_tags = scwpAssset.get("included_dcs_tags")
            print ("\nPrinting Tags Json: " + str(instance_tags))

        #Enumerate all discovered applications and Vulnerabilities

        installled_Products = scwpAssset.get("included_installed_products")
        if (installled_Products is not None):
         for product in installled_Products:
            if product.get("name") != "DCS.Cloud Agent":
                print ("\nApplication Name: "+ product.get("name"));
                vulnerabilities = product.get("is_potential_risk")
                if vulnerabilities is not None:
                    print ("Vulnerabilities: " + str(len(vulnerabilities)));
                    #for vulnerability in range (0, len(vulnerabilities)):
                      #print ("Vulnerability ID: "+ str(vulnerabilities[vulnerability].get("vulnerability_id")));
        
