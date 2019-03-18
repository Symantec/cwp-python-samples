#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to automate enforcement of CWP policy group to an instance
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#####################################################################################################

import os
import requests
import json

if __name__=="__main__":
  #First get instance ID
  #metadata = os.popen('curl -s http://169.254.169.254/latest/dynamic/instance-identity/document').read()
  instanceid = os.popen('curl -s curl http://169.254.169.254/latest/meta-data/instance-id').read()
  print "\nInstance ID: " + instanceid

  #Hard code to test policy revoke on specific server. If you are running on the same system where you want to apply policy leave instanceid as is
  #instanceid = 'i-0f72e02156824957a'

  #CWP REST API endpoint URL for auth function
  url = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'

  #TODO: Make sure you save your own CWP API keys here
  clientsecret='t6r4m————————srjhc5q'
  clientID='O2ID—————————————i0qsrc3k4p69'
  customerID='SEJ——————8STA8YCxAg'
  domainID='Dqdf—————IITB2w''

  #Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
  payload = {'client_id' : clientID, 'client_secret' : clientsecret}
  header = {"Content-type": "application/json" ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  response = requests.post(url, data=json.dumps(payload), headers=header)
  authresult=response.status_code
  token=response.json()
  if (authresult!=200) :
    print "\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n"
    exit()
  else:
    print "\nCWP API authentication successfull"

  #Extracting auth token
  accesstoken= token['access_token']
  accesstoken = "Bearer " + accesstoken
  #print "\nAccess Token: " + accesstoken

  '''
  #12/9/2017: You no longer need to get CWP internal Asset ID for calling Policy Group Apply. API now supports 'instance id'. Code commented
  #CWP Policy APIs do not accept AWS/Azure Instance IDs yet. You have to get CWP internal Asset ID using Asset API
  headerforapi = {"Content-type": "application/json","Authorization": accesstoken ,'x-epmp-customer-id' : customerID , 'x-epmp-domain-id' : domainID}
  #print "\nHeaders for Policy API: " + str(headerforapi)
  

  getInstanceIdUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/ui/assets?fields=id&where=(instance_id=\''+ instanceid +'\')'
  print "\nGet Asset ID  url: " + getInstanceIdUrl

  getInstanceIdResponse = requests.get(getInstanceIdUrl, headers=headerforapi)
  assetresponseJson = getInstanceIdResponse.json()
  assetresult=getInstanceIdResponse.status_code
  if (assetresult!=200) :
    print "\nGet CWP Asset API failed.\n"
    exit()
  else:
    print "\nCWP Asset API worked. Not let's get CWP Asset internal ID and go to calling Policy API"
  
  if (len(assetresponseJson.get("results")) > 0):
    cwpassetid = assetresponseJson.get("results")[0].get("id")
    print (cwpassetid)
  else:
    print "\nCould not get CWP Asset ID for instance: '" + instanceid
    exit()
  '''

  #First let us remove policy group if one is applied on this instance
  #REST endpoint for revoke Policy
  revokeurl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/policy/policygroups/'+ instanceid +'/all'
  print "\nRevoke policy group url: " + revokeurl
  
  revokeresponse = requests.delete(revokeurl, headers=headerforapi)
  revokeresult=revokeresponse.status_code
  print "\nRevoke Policy Group API return code: " + str(revokeresult)
  if (revokeresult!=200) :
    print "\nReovke polcy failed, but continuing to apply policy \n"
  else:
    print "\nAll existing policies on this instance '" + instanceid + "' have been revoked. Now applying policy"

  #Now let's apply a policy policy group. To get pollicy group ID go to CWP console and load the policy group details page. The Policy group ID is in the browser URL.
  #E.g. https://scwp.securitycloud.symantec.com/webportal/#/cloud/policy-group/view?policyGroupId=QYFdN2ncS5qfmz1T9Pakbw
  policygrouptoapply = 'QYFdN2ncS5qfmz1T9Pakbw'

  #REST endpoint for Apply Policy Group
  applyurl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/policy/assets/'+ instanceid +'/policy_groups/' + policygrouptoapply
  print "\nApply policy group url: " + applyurl
  applyresponse = requests.put(applyurl, headers=headerforapi)
  applyresult=applyresponse.status_code
  print "\nApply Policy Group API return code: " + str(applyresult)
  if (applyresult!=200) :
    print "\nApply polcy group failed \n"
  else:
    print "\nPolicy group: '" + policygrouptoapply + "' applied on instance: '" + instanceid + "'." 


