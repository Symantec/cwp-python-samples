#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
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

if os.name == 'nt':
	SPLUNK_HOME = 'C:\Program Files\Splunk'
else:
	SPLUNK_HOME = '/opt/splunk'

# Uncomment below 4 lines if you get SSL certificate error like "requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"

#myCABundle='/etc/ssl/certs/ca-certificates.crt'
#os.environ["REQUESTS_CA_BUNDLE"] = myCABundle
#requests.utils.DEFAULT_CA_BUNDLE_PATH = myCABundle
#requests.adapters.DEFAULT_CA_BUNDLE_PATH = myCABundle

PAGE_SIZE = 100
RETRY_COUNT = 3
#CONFIG_INI = os.path.join(SPLUNK_HOME, 'bin', 'scripts', 'ScwpGetAlertsConfig.ini')
#STATUS_INI = os.path.join(SPLUNK_HOME, 'bin', 'scripts', 'ScwpGetAlertsStatus.status')
CONFIG_INI = 'ScwpGetAlertsConfig.ini'
STATUS_INI = 'ScwpGetAlertsStatus.status'
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

getScwpAlertsRequest = {'eventTypeToQuery':16,'pageSize':PAGE_SIZE,'order':'ASCENDING','searchFilter':{}}

def updateStatusIniFile():
	config = ConfigParser.RawConfigParser()
	config.add_section(STATUS_DATES_SECTION)
	config.set(STATUS_DATES_SECTION, START_DATE, alertDatetime)
	with open(STATUS_INI, 'wb') as configfile:
    		config.write(configfile)

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
	alertTypeFilter = '(rule_name ' + getAlertProfileRuleName + ') && (type_id = 16 &&  events.type_class is_not null)'

	getScwpAlertsRequest['startDate'] = startDate
	getScwpAlertsRequest['endDate'] = datetime.now().isoformat()
	getScwpAlertsRequest['additionalFilters'] = alertTypeFilter
	alertDatetime = startDate

	pageNumber = 0
	while True:
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

