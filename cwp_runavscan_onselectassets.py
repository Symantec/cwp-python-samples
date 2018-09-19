#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Sample Python Script to enumerate CWP assets and run on demand AC scan on these assets. 
#The assets get call is filtered by OS Platform type (Windows/Unix) and optional asset tag name and value set in Azure/AWS or in CWP Console
#This script gets all instances from Azure. If you want to get Instances from AWS, change query filter to (cloud_platform in [\'AWS\'])
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service and https://apidocs.symantec.com/home/scwp#_anti_malware_scan_service
#Pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwp_runavscan_onselectassets.py  <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <Windows/Linux> [<tagname> <tagvalue>]"
#Sample Usage: python cwp_runavscan_onselectassets.py 'SEJHH8YCxAg' 'DqdfTTTTTTTB2w' 'O2ID.SEJxB2w.peu1c3kiuu4p69' 't6r4jhc5q' Unix tagname tagvalue
#Sample Usage: python cwp_runavscan_onselectassets.py 'SEJHHHHHHCxAg' 'DqdfTTTTTTTTB2w' 'O2ID.SEJxITB2wqa c3k4p69' 't6r4Uhc5q' Windows
#Sample Usage: python cwp_runavscan_onselectassets.py 'SEJHH8YCxAg' 'DqdfTTTTTTTTB2w' 'O2ID.SEJUIITB2w.peuqsk4p69' 'U2srjhc5q' Unix
##########################################################################################################################################################################

import os
import requests
import json
import sys

if __name__=="__main__":

  if (len(sys.argv) < 6):
    print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab and OS type as either windows or linux. tag name and tag value parameters are optional. Usage: python cwpagentinstall.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> [<Windows/Unix> <tagname> <tagvalue>]")
    exit()
  
  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  #Get 10 records in each page
  defaultpagesize = 10
  targetinstanceid = ""

  #Save CWP API keys here
  customerID=sys.argv[1]
  domainID=sys.argv[2]
  clientID=sys.argv[3]
  clientsecret=sys.argv[4]
  ostype=''
  tagname=''
  tagvalue=''

  #Now read optional parameters such as os type, tagname and tagvalue

  if (len(sys.argv) >= 6):
    ostype=sys.argv[5]

  if (len(sys.argv) >= 7):
    tagname=sys.argv[6]

  if (len(sys.argv) >= 8):
    tagvalue=sys.argv[7]
 
  print ("OS Type: " + ostype + ", tagname: " + tagname + ", tagvalue: " + tagvalue)

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
  
  #Get Instances in Azure account, prepare the CWP asset API rest API call parameters
  getInstanceIdUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/ui/assets'
  #print ("\nGet Asset List API call: " + getInstanceIdUrl)

  #Where clause to filter results.
  #Only select instances from Azure and those with agent installed and are in running state.
  whereclause= "(cloud_platform in ['Azure'])&(instance_state in ['Running'])&(agent_installed='Installed')"
  if (os != "") :
      whereclause= whereclause + "&(platform='" + ostype + "')"

  #Now if tagname and/or tagvalue was passed add that to the were clause
  if (tagname != ""):
      whereclause= whereclause + "&(included_dcs_tags.name='" + tagname +"')"
  if (tagvalue != ""):
      whereclause= whereclause + "&(included_dcs_tags.value='" + tagvalue +"')"
  #print ("Where Clause: " + whereclause)

  #Payload for getting one page at a time, 10 records in a page. Offset tells which record from the result set to start getting. 
  #Offset tells you home many records to skip. Limit is number of items to get starting from Offset.
  #Setup the request paramerer json object with default values
  getScwpAssetsRequest = {'limit':0,'offset':0, 'where':'', 'include':'installed_products'}

  pageNumber = 0
  getScwpAssetsRequest['where'] = whereclause
  while True:
      getScwpAssetsRequest['offset'] = pageNumber * defaultpagesize
      getScwpAssetsRequest['limit'] = defaultpagesize
      print ("Current Page Number: " + str(pageNumber))
      pageNumber += 1
      print("Request Parameters: " + json.dumps(getScwpAssetsRequest))
      getInstanceIdResponse = requests.post(getInstanceIdUrl, data=json.dumps(getScwpAssetsRequest), headers=headerforapi)
      #print (getInstanceIdResponse)
      assetresponseJson = getInstanceIdResponse.json()
      #print (assetresponseJson)
      scwpAssets = assetresponseJson['results']
      if (not scwpAssets):
        print("No Assets in current Page. Exiting..")
        print ("*********************************************************")
        break
      
      assetresult=getInstanceIdResponse.status_code
      if (assetresult!=200) :
        print ("\nGet CWP Asset API failed with error Code:" + str(assetresult) + "\n")
        exit()
      else:
        print ("\nCWP Asset API worked. Now printing API output")

      print ("Assets in Page: " + str(len(scwpAssets)))
      for scwpAssset in scwpAssets:
        #Run on demand scan only if AMD service is running on the instance
        runondemandscan='true'

        #print ('\nAsset Info Json:\n' + str(scwpAssset))
        print ("----------------------------------------------------------")

        #Save instance ID to be passed to AV Scan API
        instanceid = scwpAssset.get("instance_id")
        name = scwpAssset.get("name")
        connectionInfo = scwpAssset.get("connectionInfo")
        security_agent = scwpAssset.get("security_agent")
        print ("Instance ID: " + str(instanceid) + "\n")
        print ("Instance name: " + str(name) + "\n")
        if (connectionInfo is not None) :
            print ("Instance Connection Name: " + str(connectionInfo["name"]) + "\n")
            #print ("Connection Info JSON Object: " + str(connectionInfo))
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

            #Print Supported Agent Technologies and see if Antimalware (AMD) service is present
            if (security_agent.get("supported_technologies")) is not None:
                    #Set run scan false and only turn it to true if AMD service is available on the instance
                    runondemandscan = 'false'
                    print ("\nAgent Current Supported Protection Technologies: " +  str(security_agent.get("supported_technologies")))
                    for scwpTech in security_agent.get("supported_technologies"):
                       if scwpTech == 'AMD':
                         print ("AMD Service available on Instance: " + str(instanceid))
                         runondemandscan = 'true'
                    
            #Dump the entire CWP security agent JSON
            #print ("\nPrinting Entire Security Agent Object Json: " + str(security_agent))
        else:
            runondemandscan = 'false'

        #Print tags - CWP or AWS/Azure
        if (scwpAssset.get("included_dcs_tags")is not None):
            instance_tags = scwpAssset.get("included_dcs_tags")
            #print ("\nPrinting Tags Json: " + str(instance_tags))

        if (runondemandscan == 'true'):
           avscanUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/agents/av/scan'
           #print("\nAV Scan  url: " + avscanUrl)
           avscanpayload = {"instanceIds":[instanceid],"recurringJobDetails":{"recurringJobType":"MANUAL"}}
           #print ("\nAV Scan Payload: " + str(avscanpayload))
           avscanresponse = requests.post(avscanUrl, data=json.dumps(avscanpayload), headers=headerforapi)
           avscanresult=avscanresponse.status_code
           #print("\nRun AV Scan API return code: " + str(avscanresult))
           if (avscanresult!=200) :
             print ("\nCWP AV Scan API Failed on instance" +  str(instanceid))
           else:
             print ("\nCWP on dmand AV successfully started on Instance: " +  str(instanceid))
      print("==============================================================================") 
        
