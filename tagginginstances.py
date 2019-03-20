#!/usr/bin/env python 
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to add/delete tags to CWP assets (instances)
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Usage: python tagginginstances.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key> -instanceIds=<Comma separated Instance Ids without spaces in between> -tags=<Comma Separated Tags without spaces in between> -operation=<add or delete>
#Sample Usage to add Tag to single Instance : python tagginginstances.py -customerId=iCUdmHxxxxxBaXGQ -domainId=dAxu0xxxxxoFXBboIg -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxwvq1dpkl4 -clientSecret=1umcsxxxxxxxxxxxxxxxxxxxxxw86kdr59r6ps -instanceIds=i-02cxxxxxxr7 -tags=sampleTag1 -operation=add
#Sample Usage to delete Tag of single Instance : python tagginginstances.py -customerId=iCUdmHxxxxxBaXGQ -domainId=dAxu0xxxxxoFXBboIg -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxwvq1dpkl4 -clientSecret=1umcsxxxxxxxxxxxxxxxxxxxxxw86kdr59r6ps -instanceIds=i-02cxxxxxxr7 -tags=sampleTag1 -operation=delete
#Sample Usage to add multiple Tags to Multiple Instances : python tagginginstances.py -customerId=iCUdmHxxxxxBaXGQ -domainId=dAxu0xxxxxoFXBboIg -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxwvq1dpkl4 -clientSecret=1umcsxxxxxxxxxxxxxxxxxxxxxw86kdr59r6ps -instanceIds=i-02cxxxxxxr7,i-0e6xxxxxxce,i-0daxxxxxx5b -tags=sampleTag1,sampleTag2,sampleTag3 -operation=add
#Sample Usage to delete multiple Tags of Multiple Instances : python tagginginstances.py -customerId=iCUdmHxxxxxBaXGQ -domainId=dAxu0xxxxxoFXBboIg -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxwvq1dpkl4 -clientSecret=1umcsxxxxxxxxxxxxxxxxxxxxxw86kdr59r6ps -instanceIds=i-02cxxxxxxr7,i-0e6xxxxxxce,i-0daxxxxxx5b -tags=sampleTag1,sampleTag2,sampleTag3 -operation=delete
#####################################################################################################

import requests
import json
import time
import sys
import re
import os
import argparse

# Function to call CWP REST API and assign tags to instances
def addorupdatetags():
    dict = {}
    dict["tags"] = tags.split(",")
    dict["asset_ids"] = instanceIds.split(",")
    assettagsjson = json.dumps(dict)

    # CWP REST API endpoint URL for auth function
    url = serverURL + '/dcs-service/dcscloud/v1/oauth/tokens'

    # Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
    payload = {'client_id': clientID, 'client_secret': clientSecret}
    header = {"Content-type": "application/json", 'x-epmp-customer-id': customerID, 'x-epmp-domain-id': domainID}
    response = requests.post(url, data=json.dumps(payload), headers=header)
    authresult = response.status_code
    token = response.json()
    if (authresult != 200):
        print (
            "\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientSecret, clientId, customerId, and domainId\n")
        exit()

    # Extracting auth token
    accesstoken = token['access_token']
    accesstoken = "Bearer " + accesstoken

    # Header For API
    headerforapi = {"Authorization": accesstoken, 'x-epmp-customer-id': customerID, 'x-epmp-domain-id': domainID, "Content-Type": "application/json"}

    # CWP REST API for assigning tags to instances
    tagsurl = serverURL + '/dcs-service/dcscloud/v1/ui/tags/' + operation

    if (operation == 'add'):
        response = requests.put(tagsurl, data=assettagsjson, headers=headerforapi)
    elif(operation == 'delete'):
        response = requests.delete(tagsurl, data=assettagsjson, headers=headerforapi)
    else:
        print("Please enter appropriate operation. Valid Operations are 'add' and 'delete'.")
        exit()

    apiresult = response.status_code
    if (apiresult == 201):
        print(operation+" tags operation successful...\n")
    else:
        print(operation+" tags operation failed... Please try again\n")
        print("Failure reason : " + str(response.json()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Add and Delete Tags to Instances.')

    parser.add_argument('-serverUrl', metavar='serverUrl', default='https://scwp.securitycloud.symantec.com',
                        help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
    parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
    parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
    parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
    parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
    parser.add_argument('-instanceIds', required=True, metavar='instanceIds', help='Comma separated Instance Ids with no spaces in-between')
    parser.add_argument('-tags', required=True, metavar='tags', help='Comma separated tags with no spaces in-between')
    parser.add_argument('-operation', required=True, metavar='operation', help="Operation is 'add' or 'delete'")

    args = parser.parse_args()
    serverURL = args.serverUrl
    customerID = args.customerId
    domainID = args.domainId
    clientID = args.clientId
    clientSecret = args.clientSecret
    instanceIds = args.instanceIds
    tags = args.tags
    operation = args.operation
    operation = operation.lower()
    addorupdatetags()
