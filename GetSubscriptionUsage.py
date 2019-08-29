#!/usr/bin/env python 
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
# Script to fetch and save subscription usage.Saves the file in current location
# Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
# Usage: python GetSubscriptionUsage.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key>

# Sample Usage to get subscription usage for all domains for month-to-date: python GetSubscriptionUsage.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx
# Sample Usage to get subscription usage for given domain for month-to-date: 
# python GetSubscriptionUsage.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -usageType=all -usageDomain=dAxu0xxxx
# Sample Usage to get hourly subscription usage for given domain for last-to-last month: 
# python GetSubscriptionUsage.py -customerId=iCUdmHxxxxx -domainId=dAxu0xxxx -clientId=O2IDxxxxxxxxxxxxxxxxxxxx -clientSecret=1umcsxxxxxxxxxxx -usageType=hourly -usageDomain=dAxu0xxxx -usageMonthType=m-2
#####################################################################################################################################################################################################################

import requests, zipfile, io
import json
import time
import sys
import re
import os
import argparse
import pandas as pd

class GetSubscriptionUsage:
	def __init__(self, ServerURL, CustomerID, DomainID, ClientID, ClientSecret, usageType, usageDomain, usageMonthType):
		self.ServerURL = ServerURL
		self.CustomerID = CustomerID
		self.DomainID = DomainID
		self.ClientID = ClientID
		self.ClientSecret = ClientSecret
		self.usageType = usageType
		self.usageDomain = usageDomain
		self.usageMonthType = usageMonthType
		self.AccessToken = ""
		self.setAccessToken()
		self.APIHeader = {"Authorization": self.AccessToken, 'x-epmp-customer-id': self.CustomerID, 'x-epmp-domain-id': self.DomainID, "Content-Type": "application/json"}
		
		self.validateParams()
		
	def validateParams(self):	
		if (self.usageType != 'all' and self.usageType != 'hourly' and self.usageType != 'instance'):
			print("Invalid value for usage type: " + self.usageType)
			exit()
		
		strUsageMonthType = str(self.usageMonthType)
		if (strUsageMonthType != 'mtd' and strUsageMonthType != 'm-1' and strUsageMonthType != 'm-2'):
			print("Invalid value for month type: " + strUsageMonthType)
			exit()
			
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

	def writeToFile(self, Response, FileName):
		i = io.BytesIO(Response.content)
			
		with open(FileName,'wb') as out: ## Open temporary file as bytes
			out.write(i.read()) 

	def saveSubscriptionUsage(self):
		usageTypeUri = 'downloadUsageDetails'
		FileName = "SubscriptionUsage"
		
		if (self.usageType == 'all'):
			usageTypeUri = 'downloadUsageDetails'
			FileName = "SubscriptionUsage"
		elif (self.usageType == 'hourly'):
			usageTypeUri = 'downloadHourlyUsageDetails'
			FileName = "SubscriptionHourlyUsage"
		elif (self.usageType == 'instance'):
			usageTypeUri = 'downloadInstanceUsageDetails'
			FileName = "SubscriptionInstanceUsage"
		
		domainUri = 'forAllDomains'
		if (self.usageDomain == 'all-domains'):	
			domainUri = 'forAllDomains'
			#FileName += "_all-domains"
		else:
			domainUri = self.usageDomain
			#FileName += "_" + self.usageDomain
		
		monthType = 'mtd';	
		if (self.usageMonthType == 'mtd'):
			monthType = '0'
		elif (self.usageMonthType == 'm-1'):
			monthType = '1'
		elif (self.usageMonthType == 'm-2'):
			monthType = '2'		
	
		FileName += ".xlsx"	
		
		# CWP API to get subscription usage
		SubscriptionUsageURL = self.ServerURL + '/dcs-service/dcscloud/v1/metering/' + usageTypeUri + '/' + domainUri + '?month_type=' + monthType
		Response = requests.get(SubscriptionUsageURL, headers=self.APIHeader)
		if (Response.status_code == 200):
			print("Subscription usage retrieved successfully...")
			self.writeToFile(Response, FileName)
			print("Subscription usage saved successfully to file: " + FileName + "\n")
		else:
			print("Subscription usage could not be retrieved successfully... Please try again\n")
			print("Failure reason : " + str(Response.json()))
			exit()
		
	
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Script to fetch and save subscription usage.')

	parser.add_argument('-serverUrl', metavar='serverUrl', default='https://scwp.securitycloud.symantec.com',
						help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
	parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
	parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
	parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
	parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
	parser.add_argument('-usageType', required=False, metavar='usageType', default='all', help='Any of these: all, hourly, or instance')
	parser.add_argument('-usageDomain', required=False, metavar='usageDomain', default='all-domains', help="Either all-domains or provide domain id whose usage is to be returned")
	parser.add_argument('-usageMonthType', required=False, metavar='usageMonthType', default="0", help="Can be any of these: mtd for current month-to-date, m-1 for last month, m-2 for last to last month")

	args = parser.parse_args()
	serverURL = args.serverUrl
	customerID = args.customerId
	domainID = args.domainId
	clientID = args.clientId
	clientSecret = args.clientSecret
	usageType = args.usageType
	usageDomain = args.usageDomain
	usageMonthType = args.usageMonthType

	GetSubscriptionUsageObj = GetSubscriptionUsage(serverURL, customerID, domainID, clientID, clientSecret, usageType, usageDomain, usageMonthType)
	GetSubscriptionUsageObj.saveSubscriptionUsage()
