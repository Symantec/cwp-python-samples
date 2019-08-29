#!/usr/bin/env python 
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
# Script to extract policy settings and save in JSON file for specific policy or all policies in policy group
# Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
# Usage: python ExtractPolicySettings.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key> -policyGroupName='<Policy group name>' -policyName='<Provide Name of Policy in policy group or type 'split' for the policies in separate files or type 'all-policies' in case of all policies in one file>'

# Sample Usage to get policy settings for all policies in policy group in single JSON file: python ExtractPolicySettings.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -policyGroupName='Symantec Default Policy Group : UNIX' -policyName="all-policies"
# Sample Usage to get policy settings for all policies in separate files: python ExtractPolicySettings.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -policyGroupName='Symantec Default Policy Group : UNIX' -policyName="split"
# Sample Usage to get policy settings for one policy in a policy group: python ExtractPolicySettings.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -policyGroupName='Symantec Default Policy Group : UNIX'	-policyName="Docker Policy"
#####################################################################################################################################################################################################################

import requests
import json
import time
import sys
import re
import os
import argparse


class ExtractPolicySettings:
	def __init__(self, ServerURL, CustomerID, DomainID, ClientID, ClientSecret, PolicyGroupName):
		self.ServerURL = ServerURL
		self.CustomerID = CustomerID
		self.DomainID = DomainID
		self.ClientID = ClientID
		self.ClientSecret = ClientSecret
		self.PolicyGroupName = PolicyGroupName
		self.AccessToken = ""
		self.setAccessToken()
		self.APIHeader = {"Authorization": self.AccessToken, 'x-epmp-customer-id': self.CustomerID, 'x-epmp-domain-id': self.DomainID, "Content-Type": "application/json"}

	def getToken(self):
		# CWP REST API endpoint URL for auth function
		URL = self.ServerURL + '/dcs-service/dcscloud/v1/oauth/tokens'
		
		# Add payload, header to your CWP tenant with API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
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
		# Extracting auth token
		Token = self.getToken()
		try:
			self.AccessToken = "Bearer " + Token['access_token']
		except Exception as e:
			print ("Could not set access_token...")
			print (e)

	def getPolicyGroupDetails(self):
		# CWP REST API for get basic policy group details using policy group name
		PolicyGroupDetailsURL = self.ServerURL + '/dcs-service/dcscloud/v1/policy/policy_groups/basic?where=(name="' + self.PolicyGroupName +'")'
		Response = requests.get(PolicyGroupDetailsURL, headers=self.APIHeader)
		if (Response.status_code == 200):
			print("Policy group details fetched successfully...\n")
		else:
			print("Policy group details not fetched successfully... Please try again\n")
			print("Failure reason : " + str(Response.json()))
			exit()
		
		# Extracting policy group id from policy group details 
		PolicyGroupDetails = Response.json()
		return PolicyGroupDetails
		
	def getPolicySettings(self, PolicyGroupID, PolicyID, PolicyName):
		# CWP API to get policy settings
		PolicySettingsURL = self.ServerURL + '/dcs-service/dcscloud/v1/policy/public/policy_groups/' + PolicyGroupID + '/policies/' + PolicyID + '/settings'
		FileName = PolicyName.replace(" ","_") + ".json"
		Response = requests.get(PolicySettingsURL, headers=self.APIHeader)
		if (Response.status_code == 200):
			print("Policy settings retrieved successfully...\n")
			self.writeToFile(Response, FileName)
		else:
			print("policy settings could not be retrieved successfully... Please try again\n")
			print("Failure reason : " + str(Response.json()))
			exit()

	def writeToFile(self, Response, FileName):
		# Save policy settings JSON response in file
		with open(FileName, 'w') as File:
			File.write(Response.text)	
		print ("Successfully retrieved settings and saved in file - %s" % (os.path.realpath(File.name)))
		File.close()
		
	def getIndividualPolicySettingsInPG(self):
		PolicyGroupDetails = self.getPolicyGroupDetails()
		# Extracting policy group id
		PolicyGroupID = PolicyGroupDetails["results"][0].get("id")
		
		# CWP REST API for get policy settings for specified policy or all policies for policy group
		Policies = PolicyGroupDetails["results"][0].get("associated_policies")
		for Policy in Policies:
			PolicyName = Policy.get("name")
			PolicyID = Policy.get("id")
			self.getPolicySettings(PolicyGroupID, PolicyID, PolicyName)

	def getAllPolicySettingsInPG(self):
		PolicyGroupDetails = self.getPolicyGroupDetails()
		# Extracting policy group id
		PolicyGroupID = PolicyGroupDetails["results"][0].get("id")
		
		# CWP API to get policy settings
		PolicySettingsURL = self.ServerURL + '/dcs-service/dcscloud/v1/policy/public/policy_groups/' + PolicyGroupID + '/policies/all/settings'
		FileName = "all_policies_setttings.json"
		Response = requests.get(PolicySettingsURL, headers=self.APIHeader)
		if (Response.status_code == 200):
			print("Policies settings retrieved successfully...\n")
			self.writeToFile(Response, FileName)
		else:
			print("policies settings could not be retrieved successfully... Please try again\n")
			print("Failure reason : " + str(Response.json()))
			exit()
		
	def getPolicySettingsInPG(self, PolicyName):
		PolicyGroupDetails = self.getPolicyGroupDetails()
		# Extracting policy group id
		PolicyGroupID = PolicyGroupDetails["results"][0].get("id")
		
		# CWP REST API for get policy settings for specified policy or all policies for policy group
		Policies = PolicyGroupDetails["results"][0].get("associated_policies")
		PolicyNameFoundFlag = False
		for Policy in Policies:
			if(Policy.get("name") == PolicyName):
				PolicyName = Policy.get("name")
				PolicyID = Policy.get("id")
				self.getPolicySettings(PolicyGroupID, PolicyID, PolicyName)
				PolicyNameFoundFlag = True
				break
		if (not PolicyNameFoundFlag):
			print ("Specified policy name not found. Check spelling and case senstivity.")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Script to extract policy settings for specific policy or all policies in policy group.')

	parser.add_argument('-serverUrl', metavar='serverUrl', default='https://scwp.securitycloud.symantec.com',
						help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
	parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
	parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
	parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
	parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
	parser.add_argument('-policyGroupName', required=True, metavar='policyGroupName', help='Name of policy group')
	parser.add_argument('-policyName', required=True, metavar='policyName', help="Provide Name of Policy in policy group or type 'split' for the policies in separate files or type 'all-policies' in case of all policies in one file")

	args = parser.parse_args()
	serverURL = args.serverUrl
	customerID = args.customerId
	domainID = args.domainId
	clientID = args.clientId
	clientSecret = args.clientSecret
	policyGroupName = args.policyGroupName
	policyName = args.policyName

	ExtractPolicySettingsObj = ExtractPolicySettings(serverURL, customerID, domainID, clientID, clientSecret, policyGroupName)
	if (policyName.lower() == "all-policies"):
		ExtractPolicySettingsObj.getAllPolicySettingsInPG()
	elif (policyName.lower() == "split"):
		ExtractPolicySettingsObj.getIndividualPolicySettingsInPG()
	else:
		ExtractPolicySettingsObj.getPolicySettingsInPG(policyName)
