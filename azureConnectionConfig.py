#!/usr/bin/env python 
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
# Script to Create and Update Cloud Connection(Azure).
# Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
# Usage: python create_Azure_Connection.py -customerId=<Customer Id>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret>  -platform=Azure -connectionName=<Connection Name> -applicationId=<Application Id> -tenantId=<Tenant Id> -secret=<Application Secret> -syncIntervalHours=0 -syncIntervalMinutes=15 -operation=<create|update> -id=<connection Id>
# E.g. To update existing connection
#      python azureConnectionConfig.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p  -platform=Azure -connectionName=AzureCxxxxxxxxxxx -applicationId=nmxxxxxxx9G -tenantId=xxxxxxxx -secret=shdchhvasxjgacxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -operation=update -id=Swsdvjsdcbjxxxx
# E.g. To create new connection
#      python azureConnectionConfig.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p  -platform=Azure -connectionName=AzureCxxxxxxxxxxx -applicationId=nmxxxxxxx9G -tenantId=xxxxxxxx -secret=shdchhvasxjgacxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -operation=create 
#####################################################################################################

import requests
import json
import time
import sys
import re
import os
import argparse
import pprint

class azureConnectionConfig:

    def __init__(self, ServerURL, CustomerID, DomainID, ClientID, ClientSecret, Operation):
        self.ServerURL = ServerURL
        self.CustomerID = CustomerID
        self.DomainID = DomainID
        self.ClientID = ClientID
        self.ClientSecret = ClientSecret
        self.Operation = Operation
        if self.Operation == 'update':
            self.ConnectionId = connection_id
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

    def azureConnection(self):
        ## Create/Update Azure connection API
        azureConneURL = self.ServerURL + '/dcs-service/dcscloud/v1/cpif/cloud_connections'
        print("\nAPI : " + azureConneURL)
        print("Method : " + "POST" if self.Operation == 'create' else "PUT")
        payload={}
        azure_properties={}
        payload['cloud_platform'] = clould_platform
        payload['name'] = connection_name
        payload['pollingIntervalHours'] = syncIntervalHours
        payload['pollingIntervalMinutes'] = syncIntervalMinutes
        payload['requires_polling'] = True
        azure_properties['client_id']=azureClientId
        azure_properties['tenant_id']=azureTenantId
        azure_properties['secret']=applicationSecret
        payload['azure_properties']=azure_properties
        if self.Operation == 'update':
            payload['id'] = self.ConnectionId
        ## Paylod for Create/Update Azure connection 
        print("Payload : ")
        pprint.pprint(payload)
        print("\n")
        ## Call Azure API
        Response = requests.post(azureConneURL, data=json.dumps(payload), headers=self.APIHeader) if self.Operation == 'create' else requests.put(azureConneURL, data=json.dumps(payload), headers=self.APIHeader)
        ## Check Response
        if (Response.status_code == 200):
            print("Output : Azure connection "+ self.Operation +"d successfully...\n")
            pprint.pprint(Response.json())
            exit()
        print("Output : Failed to "+ self.Operation +" Azure connection. Please try again...")
        print("API Status code : " + str(Response.status_code))
        pprint.pprint(Response.json())


if __name__ == "__main__":
    ## Get Args Parser
    parser = argparse.ArgumentParser(description='Script to Create/Update Azure connection.')
    ## Add Arguments
    parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
    parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
    parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
    parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
    parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
    parser.add_argument('-platform', required=True, metavar='platform', help='Cloud Platform [AWS|Azure|GCP]')
    parser.add_argument('-id',  metavar='id', help='Connection Id for updating connection details')
    parser.add_argument('-connectionName', required=True, metavar='connectionName', help='Cloud connection name to be configured')
    parser.add_argument('-applicationId', required=True, metavar='applicationId', help='Azure Application Id')
    parser.add_argument('-tenantId', required=True, metavar='tenantId', help='Azure Tenant Id')
    parser.add_argument('-secret', required=True, metavar='secret', help='Azure Application Secret')
    parser.add_argument('-operation', required=True, metavar='operation', help='Create or update connection [create|update]')
    parser.add_argument('-syncIntervalHours', required=True, metavar='syncIntervalHours',type=int, help='Cloud Connection sync interval in hours')
    parser.add_argument('-syncIntervalMinutes', required=True, metavar='syncIntervalMinutes', type=int,help='Cloud Connection sync interval in Minutes')
    ## Read all args
    args = parser.parse_args()
    customerID=args.customerId
    domainID=args.domainId
    clientID=args.clientId
    clientSecret=args.clientSecret
    clould_platform = args.platform
    azureClientId = args.applicationId
    connection_name = args.connectionName
    azureTenantId = args.tenantId
    applicationSecret = args.secret
    syncIntervalHours = args.syncIntervalHours
    syncIntervalMinutes = args.syncIntervalMinutes
    operation = args.operation
    serverURL=args.serverUrl

    if operation == 'update' :
        print("Connection update operation is selected")
        if args.id is None:
            parser.error("--prox requires field -id .")
        connection_id = args.id

    ## Read Input payload json
    CloudConnectionObj = azureConnectionConfig(serverURL, customerID, domainID, clientID, clientSecret, operation)
    CloudConnectionObj.azureConnection()
