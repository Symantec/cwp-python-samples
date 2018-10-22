#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Sample Python Script to enumerate CWP assets and run on demand AC scan on these assets. 
#The assets get call can be filtered by Platform, OS Type, Tag name/value, and also by connection name
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service and https://apidocs.symantec.com/home/scwp#_anti_malware_scan_service
#The API keys are available in CWP portal's Settings->API Key tab
#Usage with minimum options: python cwp_schedule_av_scans.py -customerId=<customerId> -domainId=<domainId> -clientId=<clientId> -clientSecret=<clientSecret> -recurringJobType=<jobType> -scheduleStartTime="<start time>". Format for time is yyyy-MM-dd HH:mm:ss.
# Usage with all possible options: cwp_schedule_av_scans.py [-h] [-serverUrl serverUrl] 
#                                -customerId customerId -domainId domainId 
#                                -clientId clientId -clientSecret clientSecret
#                                -recurringJobType recurringJobType
#                                -scheduleStartTime scheduleStartTime
#                                [-scheduleEndTime scheduleEndTime]
#                                [-scheduleYear scheduleYear]
#                                [-scheduleDayOfMonth scheduleDayOfMonth]
#                                [-scheduleDayOfWeek scheduleDayOfWeek]
#                                [-scheduleMonth scheduleMonth]
#                                [-scheduleHour scheduleHour]
#                                [-scheduleMinute scheduleMinute]
#                                [-scheduleSecond scheduleSecond]
#                                [-platform platform] [-osType osType]
#                                [-tagName tagName] [-tagValue tagValue]
#                                [-connectionName connectionName]
#Sample usage 1: python cwp_schedule_av_scans.py -customerId=SEJHHHHHHA8YCxAg -domainId=DqdfTTTTTTTTTTB2w -clientId=O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojqsrc3k4465779 -clientSecret=t6r4mUUUUUUUUUg2srjhc5q -recurringJobType=DAILY -scheduleStartTime="2019-10-21 00:00:00"
#Sample usage 2: python cwp_schedule_av_scans.py -customerId=SEJHHHHHHA8YCxAg -domainId=DqdfTTTTTTTTTTB2w -clientId=O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojqsrc3k4465779 -clientSecret=t6r4mUUUUUUUUUg2srjhc5q -recurringJobType=ONETIME -scheduleStartTime="2019-10-21 00:00:00" -tagValue=MyTagValue -connectionName="My Connection"
#######################################################################################################################################################################


import platform
import os
import requests
import string
import json
import time
import sys
import argparse

  
def scheduleAVScan():
  #CWP REST API endpoint URL for auth function
  #Get 10 records in each page
  defaultpagesize = 10
  targetinstanceid = ""
  recurringJobDetails={}

  if (customerID == "" or domainID == "" or clientID == "" or clientsecret == ""):
    print ("Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab. Update the parameters in ScwpAVScanConfig.ini file. OS type can be either windows or linux. OS type, tag name, tag value, and connection name parameters are optional. Usage: python cwpagentinstall.py.")
    exit()
  
  if (recurringJobType != ""):
    recurringJobDetails['recurringJobType']=recurringJobType
  if (scheduleStartTime != ""):
    recurringJobDetails['startTime']=scheduleStartTime
  if (scheduleEndTime != ""):
    recurringJobDetails['endTime']=scheduleEndTime
  if (scheduleYear != ""):
    recurringJobDetails['year']=scheduleYear
  if (scheduleDayOfMonth != ""):
    recurringJobDetails['dayOfMonth']=scheduleDayOfMonth
  if (scheduleDayOfWeek != ""):
    recurringJobDetails['dayOfWeek']=scheduleDayOfWeek
  if (scheduleMonth != ""):
    recurringJobDetails['month']=scheduleMonth
  if (scheduleSecond != ""):
    recurringJobDetails['second']=scheduleSecond
  if (scheduleMinute != ""):
    recurringJobDetails['minute']=scheduleMinute
  if (scheduleHour != ""):
    recurringJobDetails['hour']=scheduleHour
  
  #print ("OS Type: " + osType + ", tagName: " + tagName + ", tagValue: " + tagValue + ", connectionName: " + connectionName + ", recurringJobDetails: " + json.dumps(recurringJobDetails))

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(getTokenUrl, data=json.dumps(payload), headers=header)
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
  #print ("\nGet Asset List API call: " + getInstanceIdUrl)

  #Where clause to filter results.
  #Only select instances with agent installed and are in running state.
  whereclause= "(instance_state in ['Running'])&(agent_installed='Installed')"
  
  #Filter if provided for Cloud platform, OS, Tag name/value, Connection name
  if (platform != "") :
      whereclause= whereclause + "&(cloud_platform='" + platform + "')"
  if (osType != ""):
      whereclause= whereclause + "&(platform='" + osType + "')"
  if (tagName != ""):
      whereclause= whereclause + "&(included_dcs_tags.name='" + tagName +"')"
  if (tagValue != ""):
      whereclause= whereclause + "&(included_dcs_tags.value='" + tagValue +"')"
  #print ("Where Clause: " + whereclause)

  #Payload for getting one page at a time, 10 records in a page. Offset tells which record from the result set to start getting. 
  #Offset tells you home many records to skip. Limit is number of items to get starting from Offset.
  #Setup the request paramerer json object with default values
  getScwpAssetsRequest = {'limit':0,'offset':0, 'where':'', 'include':'installed_products'}

  pageNumber = 0
  getScwpAssetsRequest['where'] = whereclause
  deviceIds = []
  instanceIds = []
  
  while True:
      getScwpAssetsRequest['offset'] = pageNumber * defaultpagesize
      getScwpAssetsRequest['limit'] = defaultpagesize
      print ("Current Page Number: " + str(pageNumber))
      pageNumber += 1
      print("Request URI: " + getInstanceIdUrl)      
      print("Request Parameters: " + json.dumps(getScwpAssetsRequest))
      getInstanceIdResponse = requests.post(getInstanceIdUrl, data=json.dumps(getScwpAssetsRequest), headers=headerforapi)
      print (getInstanceIdResponse)
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

        print ('\nAsset Info Json:\n' + str(scwpAssset))
        print ("----------------------------------------------------------")

        #Save instance ID to be passed to AV Scan API
        instanceid = scwpAssset.get("instance_id")
        deviceid = scwpAssset.get("id")
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
            if (security_agent.get("status")) is not None:
                    #Set run scan false and only turn it to true if AMD service is available on the instance
                    runondemandscan = 'false'
                    print ("\nAgent Current Supported Protection Technologies and Status': " +  str(security_agent.get("status")))
                    for scwpTech, scwpTechStatus in security_agent.get("status").items():
                       if (scwpTech == 'AMD' and scwpTechStatus.upper() == 'ONLINE'):
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

        if (connectionName != ""):
            if (connectionInfo is not None) :
                if (str(connectionInfo["name"]) != connectionName):
                    print ("Connection name does not match with the given connection name filter.\n")
                    runondemandscan = 'false'
            else:
                print ("No Connection found but filtered on connection - so not running scan on asset." + "\n")
                runondemandscan = 'false'
        
            
        if (runondemandscan == 'true'):
            deviceIds.append(deviceid)
            instanceIds.append(instanceid)
            
        
  if (len(deviceIds) > 0):  
      try:
        #print("\nAV Scan  url: " + avscanUrl)
        avscanpayload = {"deviceIds":deviceIds, "recurringJobDetails":recurringJobDetails}
        print ("\nAV Scan Payload: " + json.dumps(avscanpayload))
        avscanresponse = requests.post(avscanUrl, data=json.dumps(avscanpayload), headers=headerforapi)
        avscanresponse.raise_for_status()
      except requests.exceptions.RequestException as err:
        print ("Error Message:", err.response.json())
      except requests.exceptions.HTTPError as errh:
        print ("Http Error Message:", errh.response.json())
      except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:", errc)
      except requests.exceptions.Timeout as errt:
        print ("Timeout Error:", errt) 

      avscanresult=avscanresponse.status_code
      #print("\nRun AV Scan API return code: " + str(avscanresult))
      if (avscanresult!=200) :
        print ("\nCWP AV Scan API Failed on instances: " +  str(instanceIds) + ", Error: " + str(avscanresponse))
      else:
        print ("\nCWP AV scan successfully started on Instance id's: " +  str(instanceIds) + ", Response: " + str(avscanresponse))    
  else:
      print ("\nNo instances found matching the criterion. No scan schedule created.")

if __name__=="__main__":
   
   parser = argparse.ArgumentParser(description='Schedule AV Scan.')

   parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
   parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
   parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
   parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
   parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
   
   parser.add_argument('-recurringJobType', required=True, metavar='recurringJobType', help='Recurring Job Type. Can be any of YEARLY,MONTHLY,WEEKLY,DAILY,HOURLY,ONETIME,MANUAL')
   parser.add_argument('-scheduleStartTime', required=True, metavar='scheduleStartTime', help='Schedule start time, in format: format: yyyy-MM-dd HH:mm:ss')
   parser.add_argument('-scheduleEndTime', required=False, metavar='scheduleEndTime', help='Schedule end time, in format: format: yyyy-MM-dd HH:mm:ss')
   parser.add_argument('-scheduleYear', required=False, metavar='scheduleYear', help='Schedule year')
   parser.add_argument('-scheduleDayOfMonth', required=False, metavar='scheduleDayOfMonth', help='Schedule day of month')
   parser.add_argument('-scheduleDayOfWeek', required=False, metavar='scheduleDayOfWeek', help='Schedule day of week')
   parser.add_argument('-scheduleMonth', required=False, metavar='scheduleMonth', help='Schedule Month')
   parser.add_argument('-scheduleHour', required=False, metavar='scheduleHour', help='Schedule Hour')
   parser.add_argument('-scheduleMinute', required=False, metavar='scheduleMinute', help='Schedule minute')
   parser.add_argument('-scheduleSecond', required=False, metavar='scheduleSecond', help='Schedule second')
   
   parser.add_argument('-platform', required=False, metavar='platform', help='Cloud platform. Can be AWS/AZURE')
   parser.add_argument('-osType', required=False, metavar='osType', help='OS Type. Can be Windows/Linux')
   parser.add_argument('-tagName', required=False, metavar='tagName', help='Tag Name')
   parser.add_argument('-tagValue', required=False, metavar='tagValue', help='Tag Value')
   parser.add_argument('-connectionName', required=False, metavar='connectionName', help='Connection Name')
   
   args = parser.parse_args()
   serverURL = args.serverUrl
   customerID = args.customerId
   domainID = args.domainId
   clientID = args.clientId
   clientsecret = args.clientSecret
   
   recurringJobType = args.recurringJobType or ''
   scheduleStartTime = args.scheduleStartTime or ''
   scheduleEndTime = args.scheduleEndTime or ''
   scheduleYear = args.scheduleYear or ''
   scheduleDayOfMonth = args.scheduleDayOfMonth or ''
   scheduleDayOfWeek = args.scheduleDayOfWeek or ''
   scheduleMonth = args.scheduleMonth or ''
   scheduleHour = args.scheduleHour or ''
   scheduleMinute = args.scheduleMinute or ''
   scheduleSecond = args.scheduleSecond or ''
   
   platform = args.platform or ''
   osType = args.osType or ''
   tagName = args.tagName or ''
   tagValue = args.tagValue or ''
   connectionName = args.connectionName or ''
   
   cwpAPIUriPrefix = serverURL + '/dcs-service/dcscloud/v1';
   getTokenUrl = cwpAPIUriPrefix + '/oauth/tokens'
   getInstanceIdUrl = cwpAPIUriPrefix + '/ui/assets'
   avscanUrl = cwpAPIUriPrefix + '/agents/av/scan-now'

   print("Arguments are : \nCWP Server Url: " +serverURL+"\nCustomer Id: "+customerID+"\nDomain Id: "+domainID+"\nClient Id: "+clientID+"\nClient Secret: "+clientsecret+"\nPlatform: "+platform+"\nOS Type:"+osType+"\nTag Name: "+tagName+"\nTag Value: "+tagValue+"\nConnection Name: "+connectionName+"\nRecurring Job Type: "+recurringJobType+"\nSchedule start time: "+scheduleStartTime+"\nSchedule end time: "+scheduleEndTime+"\nSchedule year: "+scheduleYear+"\nSchedule day of month: "+scheduleDayOfMonth+"\nSchedule day of week: "+scheduleDayOfWeek+"\nSchedule month: "+scheduleMonth+"\nSchedule hour: "+scheduleHour+"\nSchedule minute: "+scheduleMinute+"\nSchedule second: "+scheduleSecond)
   scheduleAVScan()
   
print("==============================================================================") 

