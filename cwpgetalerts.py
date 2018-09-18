#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Note: Before you run this script you have to create a ScwpGetAlertsConfig.ini in the script folder. Details Below
##################################################################################################################

import json
import requests
import ConfigParser
import os
from datetime import datetime, timedelta
import time
import sys

CUSTOMER_ID = 'CUSTOMER_ID'
DOMAIN_ID = 'DOMAIN_ID'
CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'CLIENT_SECRET'

#Get Current working director
CURRENT_WORKING_FOLDER = os.getcwd()
#print "\nCurrent Working Path = " + os.getcwd()

#Enable this code if you want to use this script
#if os.name == 'nt':
#	CURRENT_WORKING_FOLDER = 'C:\Program Files\Splunk'
#else:
#	CURRENT_WORKING_FOLDER = '/opt/splunk'

PAGE_SIZE = 100
RETRY_COUNT = 3

#TODO:Load CWP API keys & filters from a config file. Create a config file 'ScwpGetAlertsConfig.ini' with this content.
#Replace the keys with your CWP from the CWP Settings page->API Keys tab 
'''
[Credentials]
CUSTOMER_ID = SEJx##############AxAg
DOMAIN_ID = Dqd####################w
CLIENT_ID = O2########################b7qan5j91g5
CLIENT_SECRET = 1n#####################6j4s7

[Alerts]
; AlertTypeFilter retrieves events of specific the event type into the Splunk. Event type can be any of these comma separated values IDS,IPS,AmazonCloudTrail,MGMT,Monitoring,AntiMalware
AlertTypeFilter = IPS,IDS,AmazonCloudTrail
GetAlertsFromDays = 10
SearchFilter=
AlertProfileRuleName=IN ["Instance Powered On", "AWS Security Group Egress Modified","AWS Security Group Egress Modified"]
;To return all Alerts use AlertProfileRuleName=
'''

#If Splunk Script use this line
#CONFIG_INI = os.path.join(CURRENT_WORKING_FOLDER, 'bin', 'scripts', 'ScwpGetAlertsConfig.ini')
CONFIG_INI = CURRENT_WORKING_FOLDER + '/ScwpGetAlertsConfig.ini'

#TODO: You can save the last polled data time in .status file so that the next run scans events from that time
# Simply Create an empty ScwpGetAlertsStatus.status file. The first run will save the date time.

#If Splunk Script use this line
#STATUS_INI = os.path.join(CURRENT_WORKING_FOLDER, 'bin', 'scripts', 'ScwpGetAlertsStatus.status')
STATUS_INI = CURRENT_WORKING_FOLDER + '/ScwpGetAlertsStatus.status'

STATUS_DATES_SECTION = 'ScwpGetAlertsDates'
CONFIG_CREDS_SECTION = 'Credentials'
CONFIG_ALERTS_SECTION = 'Alerts'
START_DATE = 'startDate'
ALERT_TYPE_FILTER = 'AlertTypeFilter'
GET_ALERTS_FROM_DAYS = 'GetAlertsFromDays'
SEARCH_FILTER= 'SearchFilter'
ALERT_PROFILE_RULE='AlertProfileRuleName'

scwpAuthUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'
getScwpAlertsUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/sccs/v1/events/search'

authHeaders = {'Content-type':'application/json'}
authRequest = {}
alertDatetime = ''

getScwpAlertsRequest = {'eventTypeToQuery':16,'pageSize':PAGE_SIZE, 'searchFilter':{}}

def updateStatusIniFile():
    #print alertDatetime
	config = ConfigParser.RawConfigParser()
	config.add_section(STATUS_DATES_SECTION)
	config.set(STATUS_DATES_SECTION, START_DATE, alertDatetime)
	with open(STATUS_INI, 'wb') as configfile:
    		config.write(configfile)

#First authenticate with CWP server with your API keys
def authenticate():
	for retry in range(RETRY_COUNT):
		authRequestJson = json.dumps(authRequest)
		authResponse = requests.post(scwpAuthUrl, data=authRequestJson, headers=authHeaders)
		if authResponse.status_code != requests.codes.ok:
			if retry >= RETRY_COUNT:
				authResponse.raise_for_status()
			time.sleep(retry * 60)
			continue
		else:
			break
	accessToken = authResponse.json()['access_token']
	authHeaders['Authorization'] = 'Bearer ' + accessToken

try:
    #Prepare headers and body for calling CWP Alert API
    #Read API keys from config file
	Config = ConfigParser.SafeConfigParser()
	Config.read(CONFIG_INI)
	customerId = Config.get(CONFIG_CREDS_SECTION, CUSTOMER_ID)
	domainId = Config.get(CONFIG_CREDS_SECTION, DOMAIN_ID)
	clientId = Config.get(CONFIG_CREDS_SECTION, CLIENT_ID)
	clientSecret = Config.get(CONFIG_CREDS_SECTION, CLIENT_SECRET)
	alertTypeFilterConfig = Config.get(CONFIG_ALERTS_SECTION, ALERT_TYPE_FILTER)
    	alertSearchFilterConfig = Config.get(CONFIG_ALERTS_SECTION, SEARCH_FILTER)
    	getAlertProfileRuleName = Config.get(CONFIG_ALERTS_SECTION, ALERT_PROFILE_RULE)
	authHeaders['x-epmp-customer-id'] = customerId
	authHeaders['x-epmp-domain-id'] = domainId
	authRequest['client_id'] = clientId
	authRequest['client_secret'] = clientSecret

	statusIni = ConfigParser.SafeConfigParser()
	statusIni.read(STATUS_INI)
	startDate = statusIni.get(STATUS_DATES_SECTION, START_DATE)
    #print startDate
	getAlertsFromDays = Config.getint(CONFIG_ALERTS_SECTION, GET_ALERTS_FROM_DAYS)
	if (startDate is None) or (startDate == ""):
		startDate = (datetime.today() - timedelta(days=getAlertsFromDays)).isoformat()
	else:
		if startDate.endswith('Z'):
			startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(milliseconds=1)).isoformat()
		else:
			startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(milliseconds=1)).isoformat()

	alertTypes = alertTypeFilterConfig.strip().split(',')
	alertTypesWithQuotes = ','.join('\"{0}\"'.format(alertType) for alertType in alertTypes)
	if getAlertProfileRuleName.strip() != '':
        	alertTypeFilter = '(rule_name ' + getAlertProfileRuleName + ') && (type_id = 16 &&  events.type_class is_not null)'
        else:
        	alertTypeFilter = '(type_id = 16 &&  events.type_class is_not null)'
    #print '\n' + alertTypeFilter
	getScwpAlertsRequest['startDate'] = startDate
	getScwpAlertsRequest['endDate'] = datetime.now().isoformat()
	getScwpAlertsRequest['additionalFilters'] = alertTypeFilter
	alertDatetime = startDate

    #Read Alerts one page at a time. 
	pageNumber = 0
	while True:
        #print '\n' + str(pageNumber)
		getScwpAlertsRequest['pageNumber'] = pageNumber
		getScwpAlertsRequestJson = json.dumps(getScwpAlertsRequest)
		scwpAlertsResponse = requests.post(getScwpAlertsUrl, data=getScwpAlertsRequestJson, headers=authHeaders)

		if scwpAlertsResponse.status_code == 401:
			authenticate()
			scwpAlertsResponse = requests.post(getScwpAlertsUrl, data=getScwpAlertsRequestJson, headers=authHeaders)
	
		if scwpAlertsResponse.status_code != requests.codes.ok:
			scwpAlertsResponse.raise_for_status()

		scwpAlertsJson = scwpAlertsResponse.json()
		scwpAlerts = scwpAlertsJson 
		totalScwpAlerts = len(scwpAlertsJson) 
	
		if totalScwpAlerts == 0:
			break 

		for scwpAlert in scwpAlerts:
			print(json.dumps(scwpAlert))
			print('\n')
			sys.stdout.flush()
			alertDatetime = scwpAlert['time']
	
		pageNumber += 1
except:
	raise
finally:
	updateStatusIniFile()

