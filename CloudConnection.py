#!/usr/bin/env python 
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
# Script to Create and Update Cloud Connection(GCP or OCI)
# Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
# Usage: python CloudConnection.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key> -operation=<create or update>
# Note : API input paylod should be in CloudConnection.json file and keep this file at same loation where this python script is available.

# Sample Usage to Create Cloud Connection(GCP or OCI) : python CloudConnection.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -operation=create
# Sample Usage to Update Cloud Connection(GCP or OCI) : python CloudConnection.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -operation=update
#####################################################################################################

import requests
import json
import time
import sys
import re
import os
import argparse
import pprint

class CloudConnection:

    def __init__(self, ServerURL, CustomerID, DomainID, ClientID, ClientSecret, Operation):
        self.ServerURL = ServerURL
        self.CustomerID = CustomerID
        self.DomainID = DomainID
        self.ClientID = ClientID
        self.ClientSecret = ClientSecret
        self.Operation = Operation
        self.payload = ""
        self.AccessToken = ""
        self.setAccessToken()
        self.APIHeader = {"Authorization": self.AccessToken, 'x-epmp-customer-id': self.CustomerID, 'x-epmp-domain-id': self.DomainID, "Content-Type": "application/json"}

    def getToken(self):
        ## CWP REST API endpoint URL for auth function
        URL = self.ServerURL + '/dcs-service/dcscloud/v1/oauth/tokens'
        ## Add payload, header to your CWP tenant with API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
        Payload = {'client_id': self.ClientID, 'client_secret': self.ClientSecret}
        Header = {"Content-type": "application/json", 'x-epmp-customer-id': self.CustomerID, 'x-epmp-domain-id': self.DomainID}
        Response = requests.post(URL, data=json.dumps(Payload), headers=Header)
        AuthResult = Response.status_code
        Token = Response.json()
        if (AuthResult != 200):
            print ("\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientSecret, clientId, customerId, and domainId\n")
            exit() 
        return Token

    def setAccessToken(self):
        ## Extracting auth token
        Token = self.getToken()
        try:
            self.AccessToken = "Bearer " + Token['access_token']
        except Exception as e:
            print("Could not set access_token...")
            print(e)

    def readInputPayloadJson(self):
        ## Read Input Payload Json from external file
        with open('CloudConnection.json') as json_file:
            inputPayloadJson = json.load(json_file)
        self.payload = inputPayloadJson
        return inputPayloadJson

    def getCloudFunction(self, cloud):
        switcher = {
            'GCP': self.gcpConnection,
            'OCI': self.ociConnection
        }
        ## Get the function from switcher based on cloud
        return switcher.get(cloud, None)

    def gcpConnection(self):
        ## Create/Update GCP connection API
        GcpConneURL = self.ServerURL + '/dcs-service/dcscloud/v1/ui/gcp/adapter_configs/public'
        print("\nAPI : " + GcpConneURL)
        print("Method : " + "POST" if self.Operation == 'create' else "PUT")
        ## Paylod for Create/Update GCP connection 
        print("Payload : ")
        pprint.pprint(self.payload)
        print("\n")
        ## Call GCP API
        Response = requests.post(GcpConneURL, data=json.dumps(self.payload), headers=self.APIHeader) if self.Operation == 'create' else requests.put(GcpConneURL, data=json.dumps(self.payload), headers=self.APIHeader)
        ## Check Response
        if (Response.status_code == 200):
            print("Output : GCP connection "+ self.Operation +"d successfully...\n")
            pprint.pprint(Response.json())
            exit()
        print("Output : Failed to "+ self.Operation +" GCP connection. Please try again...")
        print("API Status code : " + str(Response.status_code))
        pprint.pprint(Response.json())

    def ociConnection(self):
        ## Create/Update OCI connection API
        OciConneURL = self.ServerURL + '/dcs-service/dcscloud/v1/ui/ocp/adapter_configs/public'
        print("\nAPI : " + OciConneURL)
        print("Method : " + "POST" if self.Operation == 'create' else "PUT")
        ## Paylod for Create/Update OCI connection 
        print("Payload : ")
        pprint.pprint(self.payload)
        print("\n")
        ## Call OCI API
        Response = requests.post(OciConneURL, data=json.dumps(self.payload), headers=self.APIHeader) if self.Operation == 'create' else requests.put(OciConneURL, data=json.dumps(self.payload), headers=self.APIHeader)
        ## Check Response
        if (Response.status_code == 200):
            print("Output : OCI connection "+ self.Operation +"d successfully...\n")
            pprint.pprint(Response.json())
            exit()
        print("Output : Failed to "+ self.Operation +" OCI connection. Please try again...")
        print("API Status code : " + str(Response.status_code))
        pprint.pprint(Response.json())

if __name__ == "__main__":
    ## Get Args Parser
    parser = argparse.ArgumentParser(description='Script to Create/Update OCI connection.')
    ## Add Arguments
    parser.add_argument('-serverUrl', metavar='serverUrl', default='https://scwp.securitycloud.symantec.com', 
                        help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
    parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
    parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
    parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
    parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
    parser.add_argument('-operation', required=True, metavar='operation', choices=['create', 'update'], help='Operation')
    ## Read all args
    args = parser.parse_args()
    serverURL = args.serverUrl
    customerID = args.customerId
    domainID = args.domainId
    clientID = args.clientId
    clientSecret = args.clientSecret
    operation = args.operation

    ## Read Input payload json
    CloudConnectionObj = CloudConnection(serverURL, customerID, domainID, clientID, clientSecret, operation)
    Payload = CloudConnectionObj.readInputPayloadJson()

    ## Call cloud connection API
    func = CloudConnectionObj.getCloudFunction(Payload['cloud_platform'])
    func()