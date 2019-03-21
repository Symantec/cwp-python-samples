# CWP Python Samples

[![Symantec](https://img.shields.io/badge/tag-symantec-yellow.svg)](https://www.symantec.com/)
[![CWP](https://img.shields.io/badge/tag-cwp-yellow.svg)](https://www.symantec.com/products/cloud-workload-protection)
[![Python](https://img.shields.io/badge/language-python-blue.svg)](https://www.python.org/)

Python code samples for demostrating usage of [Symantec Cloud Workload Protection](https://www.symantec.com/products/cloud-workload-protection) RESTful API functions

Refer to Symantec CWP API documentation at: https://apidocs.symantec.com/home/scwp#_events_service

Before you get started you need a Symantec Cloud Workload Protection Account.
If you do not have one sign up for a trial account using this link, select the 'Cloud Workload Protection' check box: https://securitycloud.symantec.com/cc/?CID=70138000001QHo5&pr_id=F979E61C-A412-4A58-8879-B83E25B7327F#/onboard

You can also buy Cloud Workload protection from Amazon AWS Market Place that also includes free usage.
Click this link: https://aws.amazon.com/marketplace/pp/B0722D4QRN

After you have activated your account, completed AWS, Azure or Google Cloud Connection; deployed CWP agent on our cloud instances, you are ready to start using these samples

First step is to Create API access keys.
After login to CWP console, go to 'Settings' page and click on 'API Keys' tab

Copy following API secret keys and your CWP tenant ID information and secure them

- `Customer ID: SEJ*#########################7788`
- `Domain ID: Dq*####################6Yh`
- `Client ID: O***#####################y988`
- `Client Secret Key: t##################################`

-----------------------------------------------------------------------------------------------------------------------
**Code Files**

-----------------------------------------------------------------------------------------------------------------------
[cwpavexcludepath.py](cwpavexcludepath.py)

Script to update AV exclusion path for Windows Servers. Call this "agents/av/configs/" rest API to push to all Windows AV agents a list of one of more folders to skip AV Scan.
Refer to CWP REST API at https://apidocs.symantec.com/home/scwp#_anti_malware_scan_exclusion_service_for_windows

-----------------------------------------------------------------------------------------------------------------------
[cwpasset.py](cwpasset.py), [cwpasset_paged.py](cwpasset_paged.py)

1/9/2018 - Script to get CWP asset (instance) details. Script outputs instance id, instane name, AWS/Azure Connection name, Agent Version and AV definition update dates, and all installed applications and count of know vulnerabilities
Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service
Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab

Usage:
> `python cwpasset.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <instanceid>"`

*`instanceid` is optional*. If instance Id is not passed, the script enumerates all instances in AWS.
To get instances from Azure change query filter to (cloud_platform in [\'Azure\'])

Sample Usage:
> `python cwpasset.py 'SEJHHHHHHA8YCxAg' 'DqdfTTTTTTTTTTB2w' 'O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojru61uhhei0qsrc3k4p69' 't6r4mc3pfr5qmu4i6co7902huhg2srjhc5q' i-0967334540ff50b85`

1/9/2018 - Updated script to output Supported Agent protection technologies (IPS/IDS/AMD) and Cloud Platform (AWS/Azure) tags  

2/27/2018 - Added [cwpasset_page.py](cwpasset_page.py), scripts to get asset info in a paged manner.
Use this code to get asset/instances when total count is over 1000.

-----------------------------------------------------------------------------------------------------------------------
[cwpagentinstall.py](cwpagentinstall.py)

This python script downloads CWP agent installer from your CWP account, saves the files locally, runs the agent installer and reboots the instance.
You can insert this script in your AWS instance launch 'user data'.
Refer to this article for more information http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-windows-user-data.html

> NOTE: If your Linux system already has a previous version of the agent, the agent installer automatically upgrades the agent.

01/14/2018: Script has been updated to now take Customer ID, Domain ID, Client ID and Client Secret Key as arguments.
The keys are available in CWP portal's Settings -> API Key tab
Script no longer reboots the server.
This script can be used in AWS & Azure launch configs.

Usage:
> `python cwpagentinstall.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>"`

Sample Usage: 
> `python cwpagentinstall.py 'SEJHHHHHHA8YCxAg' 'DqdfTTTTTTTTTTB2w' 'O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojru61uhhei0qsrc3k4p69' 't6r4mc3pfr5qmu4i6co7902huhg2srjhc5q'`
  
 02/21/2018: Script has been updated to support detection of Oracle Enterprise Linus Distribution & Kernel. 
 
-----------------------------------------------------------------------------------------------------------------------
[cwppolicygroup.py](cwppolicygroup.py)

This python script can be used to apply a CWP policy group on a AWS instance.
The script automatically finds the AWS instance ID on which this script is executed.
You may replace that with the instance ID of another instance. This script also demonstrates the use of '`revoke`' policy API call.
To get the Policy group ID, navigate in CWP to the policy group details page and copy the policy group ID from the browser URL.
E.g. `Bm0_7LdATGOLdrwJnnKMTA` from the URL sample below https://scwp.securitycloud.symantec.com/webportal/#/cloud/policy-group/view?policyGroupId=Bm0_7LdATGOLdrwJnnKMTA

12/9/2017: CWP Policy API now supports passing the virtual machines 'Insatance ID' identifier from public cloud provider. 

E.g.
- 'i-06124fd93d7929320' for AWS, 
- '5223adcc-7585-4695-9a69-3b1484a01687' for Azure
- '4492639654741810765' for GCP 

-----------------------------------------------------------------------------------------------------------------------
[cwppolicyapply.py](cwppolicyapply.py) script is now updated to send the '`instance id`' instead of CWP internal asset ID.

-----------------------------------------------------------------------------------------------------------------------
[cwprunavscan.py](cwprunavscan.py)

This script demonstrates the run AV Scan API. This script automatically determines the AWS instance ID where this script is executed. You many specify the instance id of another instance as well. You can run AV scan as 'manual' on demand or as a 'scheduled job'

-----------------------------------------------------------------------------------------------------------------------
[cwpgetalerts.py](cwpgetalerts.py)

Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input

-----------------------------------------------------------------------------------------------------------------------
[cwpgetevents.py](cwpgetevents.py)

Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input

-----------------------------------------------------------------------------------------------------------------------
[cwptandv.py](cwptandv.py)

Script to get a list of the potential threats and vulnerabilities that may impact your instances.

Usages : 
> `python cwptandv.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <threats / vulnerabilities> <InstanceID>`
  
Example :
> `python cwptandv.py "xxxx" "xxxxx" "xxxxx" "xxxxx" "vulnerabilities" "xxxxx"`
> `python cwptandv.py "xxxx" "xxxxx" "xxxxx" "xxxxx" "threats" "xxxxx"`

-----------------------------------------------------------------------------------------------------------------------
[cwp_agent_version.py](cwp_agent_version.py)

Script to get available agent version for all/particular OS on CWP portal under download section

Usage: 
> `python cwp_agent_version.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <platform>`

Example :
> `python cwp_agent_version.py xxxx xxxxx xxxxxx xxxxxx ubuntu14`
> `python cwp_agent_version.py xxxx xxxxx xxxxxx xxxxxx all`
> `python cwp_agent_version.py xxxx xxxxx xxxxxx xxxxxx windows`

-----------------------------------------------------------------------------------------------------------------------
[cwp_aws_connection_get_create.py](cwp_aws_connection_get_create.py)

Script to automate list down AWS connection availabe for the customer and also can create connection for customer.

Usage: 
> `python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>`

Example :
> `python cwp_aws_connection_get_create.py xxx xxxxx xxxx xxxxx`

-----------------------------------------------------------------------------------------------------------------------
[cwp_aws_connection_update.py](cwp_aws_connection_update.py)

Script to automate updation of created connection with arn.
User needs to create a file "`updateconn.ini`" and update entries regarding AWS's details that user will mention while creating arn. Sample attached with name of [updateconn.ini](updateconn.ini) 

Usage:
> `python cwp_aws_connection_update.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>`

Example :
> `python cwp_aws_connection_update.py xxxxx xxxxx xxxxx xxxxxx`

-----------------------------------------------------------------------------------------------------------------------
[cwp_aws_connection_create_single_call.py](cwp_aws_connection_create_single_call.py)

Script to automate list down AWS connection availabe for the customer and also can create connection for customer.
Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection
Customer has to pass `Customer ID`, `Domain ID`, `Client ID` and `Client Secret Key` as arguments.
The keys are available in CWP portal's Settings -> API Key tab

Usage:
> `python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id> -roleArn=<Role ARN> -syncIntervalHours=<Interval in Hours> -syncIntervalMinutes=<Interval in Minutes> -requires_polling=<Periodic Sync?[True|False]> -sqsQueueName=<SQS Queue Name> -sqsQueueUrl=<SQS URL Name>`

Example for creating connection with CloudTrail Sync: 

> `python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=False -sqsQueueName=SQSQueue-xxxxxxxxxxxx -sqsQueueUrl=https://sqs.us-east-1.amazonaws.com/xxxxxxxxxxxx/CloudTrail-xxxxxxx-SQS`

Example for creating connection with Periodic Sync: 
 
> `python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=True`

-----------------------------------------------------------------------------------------------------------------------
[applyUpdatedPolicyGroupOnInstances.py](applyUpdatedPolicyGroupOnInstances.py)

Script to automate apply updated policy group on associated instances.

Example for applying policy group on associated instance.
Usage:
> `python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -policyGroupName=<Name of Policy Group which is updated>`

> `python applyUpdatedPolicyGroupOnInstances.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -policyGroupName="<Policy_Group_Name>"`

-----------------------------------------------------------------------------------------------------------------------
[cwp_schedule_av_scans.py](cwp_schedule_av_scans.py)

Script to automate scheduling of AV scans on selected instances.

Example for scheduling AV scans.
Usage:
> `python cwp_schedule_av_scans.py -customerId=<customerId> -domainId=<domainId> -clientId=<clientId> -clientSecret=<clientSecret> -recurringJobType=<jobType> -scheduleStartTime="<start time>"`

> `python cwp_schedule_av_scans.py -customerId=SEJHHHHHHA8YCxAg -domainId=DqdfTTTTTTTTTTB2w -clientId=O2ID.SEJxecAoTUUUUUUUUUUIITB2w.peu1ojqsrc3k4465779 -clientSecret=t6r4mUUUUUUUUUg2srjhc5q -recurringJobType=DAILY -scheduleStartTime="2019-10-21 00:00:00"`

--------------------------------------------------------------------------------------------------------------------
[cwp_aws_create_blank_connection.py](cwp_aws_create_blank_connection.py)

Script to automate creation of a blank AWS connection in CWP using Connection creation API with a customer provided external ID.
The API returns CWP connection ID that can be used to update the connection with Role ARN, Polling/CloudTrail settings
Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection

Customer has to pass `Customer ID`, `Domain ID`, `Client ID` and `Client Secret Key` as arguments.
The keys are available in CWP portal's Settings -> API Key tab

Usage:
> `python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id>`

E.g.
> `python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G`

E.g.
> `python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G`

--------------------------------------------------------------------------------------------------------------------

[cwpasset_agent_status.py](cwpasset_agent_status.py)

Script to get CWP asset agent installation status.
Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service

Customer has to pass `Customer ID`, `Domain ID`, `Client ID` and `Client Secret Key` as arguments.
The keys are available in CWP portal's Settings->API Key tab

Usage:
> `python cwpasset_agent_status.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <instanceid>"`

E.g.
> `python cwpasset_agent_status.py SE*****Ag Dq******w O2ID.SE*******vmuo qa*******d8 i-06***********9e`

--------------------------------------------------------------------------------------------------------------------

[cwp_schedule_av_scans.py](cwp_schedule_av_scans.py)

*Description*

Usage:
> `python ...`

E.g.
> `python ...`

--------------------------------------------------------------------------------------------------------------------
