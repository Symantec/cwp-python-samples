#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Usage: python cwpgetalerts.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key> -alertTypeFilter=<Comma Separated Event Type filter> -alertProfileRule=<Alert profile rule name> -alertFromDays=<Days in integer>
#e.g python cwpgetalerts.py -customerId=ONo***********NQapIuQ  -domainId=Eq***************Tg -clientId=O2**************************************47uu -clientSecret=1************************5 -alertTypeFilter=IPS,IDS -alertProfileRule="TestPFILRule" -alertFromDays=7
##################################################################################################################

import json
import requests
import ConfigParser
import os
from datetime import datetime, timedelta
import time
import sys
import argparse

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
def authenticate(scwpAuthUrl):
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
        parser = argparse.ArgumentParser(description='Get alerts list as per alert type filter,search filter and alert profile name')
        parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
        parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
        parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
        parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
        parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
        parser.add_argument('-alertTypeFilter', required=True, metavar='alertTypeFilter', help='Alert type filter like IPS,Antimalware etc. For multiple values use comma separated string')
        parser.add_argument('-alertProfileRule', required=True, metavar='alertProfileRule', help='Alert Profile rule name')
        parser.add_argument('-alertFromDays', required=True, metavar='alertFromDays', help='Alert from days in integer like 7,30 etc ')
        args = parser.parse_args()
        serverURL=args.serverUrl
        customerID=args.customerId
        domainID=args.domainId
        clientID=args.clientId
        clientsecret=args.clientSecret
        alerttypefilter=args.alertTypeFilter
        alertprofilerule=args.alertProfileRule
        alertsfromdays = args.alertFromDays

        scwpAuthUrl = serverURL + '/dcs-service/dcscloud/v1/oauth/tokens'
        getScwpAlertsUrl = serverURL + '/dcs-service/sccs/v1/events/search'
        
	authHeaders['x-epmp-customer-id'] = customerID
	authHeaders['x-epmp-domain-id'] = domainID
	authRequest['client_id'] = clientID
	authRequest['client_secret'] = clientsecret

	#statusIni = ConfigParser.SafeConfigParser()
	#statusIni.read(STATUS_INI)
	#startDate = statusIni.get(STATUS_DATES_SECTION, START_DATE)
	startDate = ""
        #print startDate
	getAlertsFromDays = int(alertsfromdays)
	if (startDate is None) or (startDate == ""):
		startDate = (datetime.today() - timedelta(days=getAlertsFromDays)).isoformat()
	else:
		if startDate.endswith('Z'):
			startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(milliseconds=1)).isoformat()
		else:
			startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(milliseconds=1)).isoformat()

	alertTypes = alerttypefilter.strip().split(',')
	alertTypesWithQuotes = ','.join('\"{0}\"'.format(alertType) for alertType in alertTypes)
	if alertprofilerule.strip() != '':
        	alertTypeFilter = '(rule_name =\'' + alertprofilerule + '\') && (type_id = 16 &&  events.type_class is_not null)'
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
			authenticate(scwpAuthUrl)
			scwpAlertsResponse = requests.post(getScwpAlertsUrl, data=getScwpAlertsRequestJson, headers=authHeaders)
	
		if scwpAlertsResponse.status_code != requests.codes.ok:
			print "Get Alerts API is failed"
                        scwpAlertsResponse.raise_for_status()
                else:
                        print "Get Alerts API is successful"

		scwpAlertsJson = scwpAlertsResponse.json()
		scwpAlerts = scwpAlertsJson 
		totalScwpAlerts = len(scwpAlertsJson) 
	
		if totalScwpAlerts == 0:
			break 

		for scwpAlert in scwpAlerts:
			#print(json.dumps(scwpAlert))
			#print('\n')
			sys.stdout.flush()
			alertDatetime = scwpAlert['time']
	
		pageNumber += 1
except:
	raise
finally:
	updateStatusIniFile()

