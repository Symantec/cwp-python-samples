Sample code projects for building security applications using Symantec Cloud Workload Protection REST API

Refer to Symantec CWP API documentation at: https://apidocs.symantec.com/home/scwp#_events_service

Before you get started you need a Symantec Cloud Workload Protection Account. If you do not have one sign up for a trial account using this link, select the 'Cloud Workload Protection' check box: https://securitycloud.symantec.com/cc/?CID=70138000001QHo5&pr_id=F979E61C-A412-4A58-8879-B83E25B7327F#/onboard

You can also buy Cloud Workload protection from Amazon AWS Market Place that also includes free usage. Click this link: https://aws.amazon.com/marketplace/pp/B0722D4QRN

After you have activated your account, completed AWS, Azure or Google Cloud Connection; deployed CWP agent on our cloud instances, you are ready to start using these samples

First step is to Create API access keys. After login to CWP console, go to 'Settings' page and click on 'API Keys' tab

Copy following API secret keys and your CWP tenant ID information and secure them

Customer ID: SEJ*#########################7788

Domain ID: Dq*####################6Yh

Client ID: O***#####################y988

Client Secret Key: t##################################

-----------------------------------------------------------------------------------------------------------------------
Code Files


Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
#sage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id> -roleArn=<Role ARN> -syncIntervalHours=<Interval in Hours> -syncIntervalMinutes=<Interval in Minutes> -requires_polling=<Periodic Sync?[True|False]> -sqsQueueName=<SQS Queue Name> -sqsQueueUrl=<SQS URL Name>
Example:
 #1 python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=False -sqsQueueName=SQSQueue-xxxxxxxxxxxx -sqsQueueUrl=https://sqs.us-east-1.amazonaws.com/xxxxxxxxxxxx/CloudTrail-xxxxxxx-SQS
 #2 python cwp_aws_connection_create_single_call.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=True

-----------------------------------------------------------------------------------------------------------------------
cwp_aws_connection_create_single_call.py
Script to automate apply updated policy group on associated instances.
Usage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -policyGroupName=<Name of {olicy Group which is updated> 
Example:
 python applyUpdatedPolicyGroupOnInstances.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -policyGroupName="<Policy_Group_Name>"

-----------------------------------------------------------------------------------------------------------------------
cwpavexcludepath.py
Script to update AV exclusion path for Windows Servers. Call this "agents/av/configs/" rest API to push to all Windows AV agents a list of one of more folders to skip AV Scan.
Refer to CWP REST API at https://apidocs.symantec.com/home/scwp#_anti_malware_scan_exclusion_service_for_windows

-----------------------------------------------------------------------------------------------------------------------
cwpasset.py, cwpasset_paged.py

1/9/2018 - Script to get CWP asset (instance) details. Script outputs instance id, instane name, AWS/Azure Connection name, Agent Version and AV definition update dates, and all installed applications and count of know vulnerabilities
Refer to CWP REST API at: https://apidocs.symantec.com/home/scwp#_fetch_assets_service
Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
Usage: python cwpasset.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client Id> -clientSecret=<Client Secret Key> -platform=<Cloud Platform> -instanceId=<instanceid>"
instanceid is optional. if instance Id is not passed, the script enumerates all instances in AWS. To get instances from Azure chage query filter to (cloud_platform in [\'Azure\'])
Example:
 python cwpasset.py -customerId=iCUdmHxxxxxBaXGQ  -domainId=dAxu0xxxxxoFXBboIg -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxw.xxxxxxxxxxxxxxxxxxxxxwvq1dpkl4 -clientSecret=1umcsxxxxxxxxxxxxxxxxxxxxxw86kdr59r6ps -platform=AWS -instanceId=i-xxxxxxxx

1/9/2018 - Updated script to output Supported Agent protection technologies (IPS/IDS/AMD) and Cloud Platform (AWS/Azure) tags  

2/27/2018 - Added cwpasset_page.py, scripts to get asset info in a paged manner. Use this code to get asset/instances when total count is over 1000.
  
-----------------------------------------------------------------------------------------------------------------------

cwpagentinstall.py This python script downloads CWP agent installer from your CWP account, saves the files locally, runs the agent installer and reboots the instance. You can insert this script in your AWS instance launch 'user data'. Refer to this article for more information http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-windows-user-data.html
NOTE: If your Linux system already has a previous version of the agent, the agent installer automatically upgrades the agent.

01/14/2018: Script has been updated to now take Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab
Script no longer reboots the server. This script can be used in AWS & Azure launch configs.
Usage: python cwpagentinstall.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key>"
Example:
 python cwpagentinstall.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c

  
 02/21/2018: Script has been updated to support detection of Oracle Enterprise Linus Distribution & Kernel. 
 
-----------------------------------------------------------------------------------------------------------------------
cwppolicygroup.py This python script can be used to apply a CWP policy group on a AWS instance. The script automatically finds the AWS instance ID on which this script is executed. You may replace that with the instance ID of another instance. This script also demonstrates the use of 'revoke' policy API call. To get the Policy group ID, navigate in CWP to the policy group details page and copy the policy group ID from the browser URL. E.g. Bm0_7LdATGOLdrwJnnKMTA from the URL sample below https://scwp.securitycloud.symantec.com/webportal/#/cloud/policy-group/view?policyGroupId=Bm0_7LdATGOLdrwJnnKMTA

12/9/2017: CWP Policy API now supports passing the virtual machines 'Insatance ID' identifier from public cloud provider. 
E.g.'i-06124fd93d7929320' for AWS, '5223adcc-7585-4695-9a69-3b1484a01687' for Azure and '4492639654741810765' for GCP. 
cwppolicyapply.py script is now updated to send the 'instance id' instead of CWP internal asset ID.

-----------------------------------------------------------------------------------------------------------------------
cwprunavscan.py 
This script demonstrates the run AV Scan API. This script automatically determines the AWS instance ID where this script is executed. You many specify the instance id of another instance as well. You can run AV scan as 'manual' on demand or as a 'scheduled job'
Usage:  python cwprunavscan.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -instanceId=<instanceid on which you want to run AV scan> or -filename=<filename in which you have stored instance id, it should be present on current location where you are running this script>
Example:
 python cwprunavscan.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -instanceId=i-0e1268226b99bf24c 
OR
 python cwprunavscan.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -filename=abc.txt 
-----------------------------------------------------------------------------------------------------------------------
cwpgetalerts.py
Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input
Usage: python cwpgetalerts.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key> -alertTypeFilter=<Comma Separated Event Type filter> -alertProfileRule=<Alert profile rule name> -alertFromDays=<Days in integer>
Example:
 python cwpgetalerts.py -customerId=ONo***********NQapIuQ  -domainId=Eq***************Tg -clientId=O2**************************************47uu -clientSecret=1************************5 -alertTypeFilter=IPS,IDS -alertProfileRule="TestPFILRule" -alertFromDays=7

-----------------------------------------------------------------------------------------------------------------------
cwpgetevents.py
Script to download CWP Alerts using CWP REST API. This script can be used to input data into splunk as script input

-----------------------------------------------------------------------------------------------------------------------
cwptandv.py
Script to get a list of the potential threats and vulnerabilities that may impact your instances.
Usage:  python cwptandv.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -threatORvulnerability=<threats/vulnerabilities> -instanceId=<instanceid on which you want to run AV scan> 
Example:
 python cwptandv.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -threatORvulnerability=threats -instanceId=i-0e1268226b99bf24c 
OR
python cwptandv.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -threatORvulnerability=vulnerabilities -instanceId=i-0e1268226b99bf24c 


-----------------------------------------------------------------------------------------------------------------------
cwp_agent_version.py
Script to get available agent version for all/particular OS on CWP portal under download section

Usage: python cwp_agent_version.py -customerId=<Customer ID> -domainId=<Domain ID> -clientId=<Client ID> -clientSecret=<Client Secret Key>" -platform=<All or particular platform like rhel6,rhel7 etc as mentioned in below script>

Example:
 python cwp_agent_version.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -platform=All
 python cwp_agent_version.py -customerId=7hxxxxxxxxxxxxxxxxw  -domainId=pSxxxxxxxxxxxxxxxxtA -clientId=O2ID.7hxxxxxxxxxxxxxxxxw.pSxxxxxxxxxxxxxxxxtA.u12nq9xxxxxxxxxxxxxxxxgm97b0 -clientSecret=11exxxxxxxxxxxxxx0h5d2c -platform=Ubuntu14


-----------------------------------------------------------------------------------------------------------------------
cwp_aws_connection_get_create.py
Script to automate list down AWS connection availabe for the customer and also can create connection for customer.
Usage: 
python cwp_aws_connection_get_create.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key>
python cwp_aws_connection_get_create.py -customerId=<Customer ID>  -domainId=<Domain ID> -clientId=<Client Id> -clientSecret=<Client Secret Key> -platform=AWS
Example :
 python cwp_aws_connection_get_create.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -platform=AWS


-----------------------------------------------------------------------------------------------------------------------
cwp_aws_connection_update.py
Script to automate updation of created connection with arn. User need to create a file "updateconn.ini" and update entries regarding AWS's details that user will mention while creating arn. Sample attached with name of "updateconn.ini" 
Usage:
Usage: python cwp_aws_connection_create_single_call.py -customerId=<customerId>  -domainId=<Domain Id> -clientId=<Client Id> -clientSecret=<Client Secret> -platform=AWS -connectionName=<Cloud Connection Name> -externalId=<External Id> -roleArn=<Role ARN> -syncIntervalHours=<Interval in Hours> -syncIntervalMinutes=<Interval in Minutes> -requires_polling=<Periodic Sync?[True|False]> -sqsQueueName=<SQS Queue Name> -sqsQueueUrl=<SQS URL Name>
Example :
 #For CloudTrail Sync
 python cwp_aws_connection_update.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -id=connectionid -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=False -sqsQueueName=SQSQueue-xxxxxxxxxxxx -sqsQueueUrl=https://sqs.us-east-1.amazonaws.com/xxxxxxxxxxxx/CloudTrail-xxxxxxx-SQS
 #For Periodic Sync
 python cwp_aws_connection_update.py -customerId=xxxxxxxxxxxx-iY2nw  -domainId=DxxxxxxxxxxxxJNZxx -clientId=O2ID.xxxxxxxxxxxxxxxxxxxxxw.DxxxxxxxxxxxxJNZxx.nxxxxxxxxxxxxxxxxxx -clientSecret=1lxxxxxxxxxxxxxxxxxxx1p -id=connectionid -platform=AWS -connectionName=AWSCxxxxxxxxxxx -externalId=nmxxxxxxx9G -roleArn=arn:aws:iam::xxxxxxxxxxxx:role/Role-For-DCS.Cloud-xxxxxxxx -syncIntervalHours=0 -syncIntervalMinutes=15 -requires_polling=True




