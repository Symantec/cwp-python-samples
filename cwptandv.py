#!/usr/bin/env python
#
# Copyright 2018 Symantec Corporation. All rights reserved.
#
#Script to get a list of the potential threats and vulnerabilities that may impact your instances.
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key and InstnanceID as arguments. The keys are available in CWP portal's Settings->API Key tab
#Usage: python cwptandv.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <threats / vulnerabilities> <InstanceID>
#Same script can be used to fetch both threats and vulnerabilities depending upon parameter <threats / vulnerabilities> <InstanceID>
#Sample Usage: python cwptandv.py 'SEJHHHHHHA8YCxAg' 'DqdfTTTTTTTTTTB2w' 'O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojqsrc3k4p69' 't6r4mUUUUUUUUUg2srjhc5q' 'threats' 'xxxxx'
#####################################################################################################

import os
import requests
import json
import sys

if __name__=="__main__":

  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  t = len(sys.argv)
  if len(sys.argv) != 7 :
   print ("Please provide valid input parameters. For e.g. python cwptandv.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <threats / vulnerabilities> <InstanceID>")
   sys.exit()

  threatorvuln = ""
  #Save CWP API keys here
  customerID=sys.argv[1]
  domainID=sys.argv[2]
  clientID=sys.argv[3]
  clientsecret=sys.argv[4]
  gettandvUrl=""
  instanceid = sys.argv[6]

  # Set API URL depending upon the input param
  if sys.argv[5] == "threats" :
   gettandvUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/threats'
  elif sys.argv[5] == "vulnerabilities" :
   gettandvUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/vulnerabilities'
  else :
   print ("\nPlease provide valid input parameters use option threats/vulnerabilities\n")
   sys.exit()
  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id IntanceID
  payload = {'client_id' : clientID, 'client_secret' : clientsecret, 'instances' : ['4492639654741810765']}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
    sys.exit()
  else:
    print ("\nCWP API authentication successfull")

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken

  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  apipayload= {"instances" : [instanceid] }
  apipayload=json.dumps(apipayload)
 
  print ("apipayload  " +  apipayload)
  #Get threats and vulnerabilities details using filters provided in filters.json file. If this file not found or empty API will fetch all threas or vulnerabilities.
  gettnvResponse = requests.post(gettandvUrl, apipayload, headers=headerforapi)
  print(str(gettnvResponse))
  tnvresponseJson = gettnvResponse.json()
  tnvresult = gettnvResponse.status_code

  if (tnvresult!=200) :
    print ("\nGet CWP threats and vulnerabilities API failed with error Code:" + str(tnvresult) + "\n")
    sys.exit()
  else:
    print ("\nCWP "+sys.argv[5] +" API worked. Now printing API output")

if sys.argv[5] == "threats" :
    for item in range (0, len(tnvresponseJson.get("threatList"))):
      print ("----------------------------------------------------------")
      title = tnvresponseJson.get("threatList")[item].get("title")
      print("\nTitle :" + title)
      if(tnvresponseJson.get("threatList")[item].get("description") is not None):
        desc = tnvresponseJson.get("threatList")[item].get("description")
        print("Description :" + str(desc.encode('utf-8')))
      if(tnvresponseJson.get("threatList")[item].get("severity_level") is not None):
        severity = tnvresponseJson.get("threatList")[item].get("severity_level")
        print("Severity Level :" + severity)
      if(tnvresponseJson.get("threatList")[item].get("instances") is not None):
        instancelist = tnvresponseJson.get("threatList")[item].get("instances")
        print("Affected Instance List :" + str(instancelist))
      if(tnvresponseJson.get("threatList")[item].get("applications") is not None):
        applications = tnvresponseJson.get("threatList")[item].get("applications")
        print("Affected applications :" + str(applications))
      if(tnvresponseJson.get("threatList")[item].get("vulnerabilities") is not None):
        vulnerabilities = tnvresponseJson.get("threatList")[item].get("applications")
        print("Associated vulnerabilities :" + str(vulnerabilities))

if sys.argv[5] == "vulnerabilities" :
      for item in range (0, len(tnvresponseJson.get("vulnerabilities"))):
        print ("----------------------------------------------------------")
        title = tnvresponseJson.get("vulnerabilities")[item].get("title")
        print("\nTitle :" + title)
        if(tnvresponseJson.get("vulnerabilities")[item].get("description") is not None):
          desc = tnvresponseJson.get("vulnerabilities")[item].get("description")
          print("Description :" + str(desc.encode('utf-8')))
        if(tnvresponseJson.get("vulnerabilities")[item].get("cves") is not None):
          cves = tnvresponseJson.get("vulnerabilities")[item].get("cves")
          print("CVES :" + str(cves))
        if(tnvresponseJson.get("vulnerabilities")[item].get("severity_level") is not None):
          severity = tnvresponseJson.get("vulnerabilities")[item].get("severity_level")
          print("Severity Level :" + severity)
        if(tnvresponseJson.get("vulnerabilities")[item].get("instances") is not None):
          instancelist = tnvresponseJson.get("vulnerabilities")[item].get("instances")
          print("Affected Instance List :" + str(instancelist))
        if(tnvresponseJson.get("vulnerabilities")[item].get("applications") is not None):
          applications = tnvresponseJson.get("vulnerabilities")[item].get("applications")
          print("Affected Applications :" + str(applications))
        if(tnvresponseJson.get("vulnerabilities")[item].get("threats") is not None):
          threats = tnvresponseJson.get("vulnerabilities")[item].get("threats")
          print("Associated Threats :" + str(threats))
