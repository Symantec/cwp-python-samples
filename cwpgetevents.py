#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
#Script to download CWP Events using CWP REST API. This script can be used to input data into splunk as script input 
#Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
#Note: Before you run this script you have to create a ScwpGetEventsConfig.ini in the script folder. Details Below
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
#       CURRENT_WORKING_FOLDER = 'C:\Program Files\Splunk'
#else:
#       CURRENT_WORKING_FOLDER = '/opt/splunk'

PAGE_SIZE = 100
RETRY_COUNT = 3

#If Splunk Script use this line
#CONFIG_INI = os.path.join(CURRENT_WORKING_FOLDER, 'bin', 'scripts', 'ScwpGetEventsConfig.ini')
#CONFIG_INI = CURRENT_WORKING_FOLDER + '/ScwpGetEventsConfig.ini'

#TODO: You can save the last polled data time in .status file so that the next run scans events from that time
# Simply Create an empty ScwpGetEventsStatus.status file. The first run will save the date time.

#If Splunk Script use this line
#STATUS_INI = os.path.join(CURRENT_WORKING_FOLDER, 'bin', 'scripts', 'ScwpGetEventsStatus.status')
STATUS_INI = CURRENT_WORKING_FOLDER + '/ScwpGetEventsStatus.status'

STATUS_DATES_SECTION = 'ScwpGetEventsDates'
CONFIG_CREDS_SECTION = 'Credentials'
CONFIG_EVENTS_SECTION = 'Events'
START_DATE = 'startDate'
EVENT_TYPE_FILTER = 'EventTypeFilter'
GET_EVENTS_FROM_DAYS = 'GetEventsFromDays'

authHeaders = {'Content-type':'application/json'}
authRequest = {}
eventDatetime = ''

getScwpEventsRequest = {'pageSize':PAGE_SIZE, 'order':'ASCENDING','displayLabels':'false', 'searchFilter':{}}

def updateStatusIniFile():
	config = ConfigParser.RawConfigParser()
	config.add_section(STATUS_DATES_SECTION)
	config.set(STATUS_DATES_SECTION, START_DATE, eventDatetime)
	with open(STATUS_INI, 'wb') as configfile:
    		config.write(configfile)

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
        parser = argparse.ArgumentParser(description='Get events list as per event filter')
        parser.add_argument('-serverUrl', metavar='serverUrl',default='https://scwp.securitycloud.symantec.com', help='CWP environment URL. Required if customer onboarded other than US region.(default CWP US region deployment.)')
        parser.add_argument('-customerId', required=True, metavar='customerId', help='CWP account customer Id')
        parser.add_argument('-domainId', required=True, metavar='domainId', help='CWP account domain Id')
        parser.add_argument('-clientId', required=True, metavar='clientId', help='CWP account client Id')
        parser.add_argument('-clientSecret', required=True, metavar='clientSecret', help='CWP account client secret')
        parser.add_argument('-eventTypeFilter', required=True, metavar='eventTypeFilter', help='Event type filter like IPS,Antimalware etc. For multiple values use comma separated string')
        parser.add_argument('-eventsFromDays', required=True, metavar='eventsFromDays', help='Event from days in integer like 7,30 etc ')
        args = parser.parse_args()
        serverURL=args.serverUrl
        customerID=args.customerId
        domainID=args.domainId
        clientID=args.clientId
        clientsecret=args.clientSecret
        eventtypefilter=args.eventTypeFilter
        eventsfromdays = args.eventsFromDays
        
        scwpAuthUrl = serverURL + '/dcs-service/dcscloud/v1/oauth/tokens'
        getScwpEventsUrl = serverURL + '/dcs-service/dcscloud/v1/event/query'

        print("Arguments are : \nCWP Server Url:" +serverURL+"\n")
        print("Customer ID:" + customerID + "\n")
        print("Domain ID:" + domainID + "\n")
        print("Client ID:" + clientID + "\n")
        print("ClientSecret Key:" + clientsecret + "\n")
        print("EventTypeFilter:" + eventtypefilter + "\n")
        print("Events From Days :" + eventsfromdays + "\n")
        
        authHeaders['x-epmp-customer-id'] = customerID
        authHeaders['x-epmp-domain-id'] = domainID
        authRequest['client_id'] = clientID
        authRequest['client_secret'] = clientsecret

        #statusIni = ConfigParser.SafeConfigParser()
        #statusIni.read(STATUS_INI)
        #startDate = statusIni.get(STATUS_DATES_SECTION, START_DATE)
        startDate = ""
        getEventsFromDays = int(eventsfromdays)
        if (startDate is None) or (startDate == ""):
                startDate = (datetime.today() - timedelta(days=getEventsFromDays)).isoformat()
        else:
                if startDate.endswith('Z'):
                        startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(milliseconds=1)).isoformat()
                else:
                        startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(milliseconds=1)).isoformat()

        eventTypes = eventtypefilter.strip().split(',')
        eventTypesWithQuotes = ','.join('\"{0}\"'.format(eventType) for eventType in eventTypes)
        eventTypeFilter = 'type_class IN [' + eventTypesWithQuotes + '] && (type =\"1008\")'

        getScwpEventsRequest['startDate'] = startDate
        getScwpEventsRequest['endDate'] = datetime.now().isoformat()
        getScwpEventsRequest['additionalFilters'] = eventTypeFilter
        eventDatetime = startDate

        pageNumber = 0
        while True:
                getScwpEventsRequest['pageNumber'] = pageNumber
                getScwpEventsRequestJson = json.dumps(getScwpEventsRequest)
                scwpEventsResponse = requests.post(getScwpEventsUrl, data=getScwpEventsRequestJson, headers=authHeaders)

                if scwpEventsResponse.status_code == 401:
                        authenticate(scwpAuthUrl)
                        scwpEventsResponse = requests.post(getScwpEventsUrl, data=getScwpEventsRequestJson, headers=authHeaders)

                if scwpEventsResponse.status_code != requests.codes.ok:
                        print "Get events API is failed"
                        scwpEventsResponse.raise_for_status()
                else:
                        print "Get Events API is successful"

                scwpEventsJson = scwpEventsResponse.json()
                scwpEvents = scwpEventsJson['result']
                totalScwpEvents = scwpEventsJson['total']
                if totalScwpEvents == 0:
                        break 

                for scwpEvent in scwpEvents:
                        #print(json.dumps(scwpEvent))
                        #print('\n')
                        sys.stdout.flush()
                        eventDatetime = scwpEvent['time']

                pageNumber += 1
except:
	raise
finally:
	updateStatusIniFile()
