#!/usr/bin/env python 
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
# Script to parse the extracted policy settings from JSON file into a more readable CSV format.
# The output will be saved in a file named 'setttings.csv' at the same location as that of the input settings JSON file.
# Usage: python ParsePolicySettings.py -settingsFileName='<Settings file name>'

# Sample Usage to parse policy settings from JSON file: python ParsePolicySettings.py -settingsFileName='all_policies_setttings.json'
#####################################################################################################################################

import string
import json
import time
import argparse

global global_csv

class Entry:
	def __init__(self, index, value):
		self.index = index
		self.value = value

def save_csv():
	with open("setttings.csv", 'w') as f:
		f.write( global_csv )
	print ( "File saved !!" )
	return

def new_csv_line():
	global global_csv
	global_csv = global_csv + "\n"
	return

def add_csv_line( entries ):
	new_csv_line()
	global global_csv
	for entry in entries:
		index = entry.index
		value = entry.value
		for i in range( index ):
			global_csv = global_csv + ","
		
		global_csv = global_csv + value
		
	return

def print_section_header( section_index, section ):
	header_entry = Entry( section_index, section['titleView'] )
	add_csv_line( [header_entry] )
		
	return
	
def print_section( section_index, section ):
	if( 'on' == section['hidden'] ):
		return
	
	print_section_header( section_index, section )
	
	for settings in section['settings']:
		if( 'on' == settings['hidden'] ):
			continue
		print_settings( section_index+1, settings )
	
	child_section_index = section_index+1
	for child_section in section['sections']:
		print_section( child_section_index, child_section )
		
	return

def print_parameter ( param_index, parameter ):
	for pvs in parameter['parametervalues']:
		entries = []
		for pv in pvs['parametervalue']:
			entries.append ( Entry(param_index, pv['value']) )
			
		add_csv_line( entries )
	
	return
	
def print_settings(init_index, settings):
	name_entry = Entry(init_index, settings['nameView'])
	if 'state' in settings:
		state_entry = Entry( init_index+1, settings['state'] )
	
	add_csv_line( [name_entry, state_entry] )
	
	if 'policyParameters' in settings:
		for policyParameter in settings['policyParameters']:
			print_parameter( init_index+1, policyParameter )
		
	for child_settings in settings['settings']:
		print_settings( init_index+1, child_settings )
		
	return

def print_av_settings( setting_v ):
	if 'enableAutoProtect' in setting_v:
		key_entry = Entry( 1, 'enableAutoProtect' )
		value_entry = Entry( 2, str(setting_v['enableAutoProtect']) )
		add_csv_line( [key_entry, value_entry] )
		
	if 'scanExclusions' in setting_v:
		key_entry = Entry( 1, 'scanExclusions' )
		add_csv_line( [key_entry] )
		for scan_exclusion in setting_v['scanExclusions']:
			value_entry = Entry( 2, scan_exclusion )
			add_csv_line( [value_entry] )
	
	if 'scanExternalDrives' in setting_v:
		key_entry = Entry( 1, 'scanExternalDrives' )
		value_entry = Entry( 2, str(setting_v['scanExternalDrives']) )
		add_csv_line( [key_entry, value_entry] )
	
	if 'quarantinePath' in setting_v:
		key_entry = Entry( 1, 'quarantinePath' )
		value_entry = Entry( 2, setting_v['quarantinePath'] )
		add_csv_line ( [key_entry, value_entry] )
				
	if 'scanInclusions' in setting_v:
		key_entry = Entry( 1, 'scanInclusions' )
		add_csv_line ( [key_entry] )
		for scan_inclusion in setting_v['scanInclusions']:
			value_entry = Entry( 2, scan_inclusion )
			add_csv_line( [value_entry] )	
	return	

def parse_settings( settingsFileName ):
	with open( settingsFileName, 'r' ) as f:
		policies =  json.load( f )
		
		for policy in policies:
			new_csv_line()
			policy_type = policy['policy_type']
			if ( policy_type == 'AV' ):
				e = Entry( 0, policy['policy_name'] )
				add_csv_line( [e] )
				print_av_settings( policy['policy_settings'] )
			else:
				new_csv_line()
				e = Entry( 0, policy['policy_name'] )
				add_csv_line( [e] )
				for setting in policy['policy_settings']:
					for setting_v in setting:
						if 'sections' in setting_v:
							for section in setting_v['sections']:
								print_section( 1, section )
		
	save_csv()	
	
	print ("Done...")
	
if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Script to parse policy settings and transform to a CSV format.')
	
	parser.add_argument('-settingsFileName', required=True, metavar='settingsFileName', help='JSON file containing the exported settings')
	
	args = parser.parse_args()
	settingsFileName = args.settingsFileName
	
	global_csv=""
	parse_settings( settingsFileName )