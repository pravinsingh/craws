""" This rule checks for any ec2 instance scheduled for maintenance.
"""

__version__ = '1.0.0'
__author__ = 'Antony'
import boto3
import datetime
import craws

def handler(event, context):
    logger = craws.get_logger(name='EC2Maintenance')
    logger.debug('EC2 Maintenance Events Check Started')

    sts = boto3.client('sts')    

    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/EC2Maintenance.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'EC2 Instances Scheduled for Maintenance'}
            results['Area'] = 'EC2'
            results['Description'] = 'This rule checks if there are any EC2 Instances scheduled for Maintenance'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='ec2_maintenance')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = total_count = 0            
            message = ''
            for region in regions:
                
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                conn = boto3.resource('ec2',region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])                
                
                try:
                    result = []

                    #Finding total count of EC2 Instances Running
                    instances = conn.instances.filter(Filters=[{'Name': 'instance-state-name','Values': ['running']}])
                    RunningInstances = []
                    for instance in instances:
                        RunningInstances.append(instance.id)
                        total_count += 1

                    # Filtering for only maintenance events
                    res_status = ec2_client.describe_instance_status(Filters=[{'Name':'event.code','Values':['instance-reboot','system-reboot','system-maintenance',
                                'instance-retirement','instance-stop']}])

                    if len(res_status['InstanceStatuses']) > 0:
                        for checkEvents in res_status['InstanceStatuses']:
                            if 'Events' in checkEvents:
                                for eventItems in checkEvents['Events']:
                                    tag_name = 'Tag Not Found'
                                    instance_event = ec2_client.describe_instances(Filters=[{'Name':'instance-id','Values': [checkEvents['InstanceId']]}]) 
                                    tag_name = [tag['Value'] for i in instance_event['Reservations'] for j in i['Instances'] for tag in j['Tags'] if tag['Key'] == 'Name'] 
                                    tag_value = ''.join(map(str, tag_name))
                                    message += checkEvents['InstanceId'] + ' ' + checkEvents['AvailabilityZone'] + ' ' + tag_value +  ' '  + eventItems['Code'] +\
                                    ' ' + eventItems['Description'] + ' ' + eventItems['NotBefore'].strftime('%m/%d/%Y') + ' ''\n'
                                    
                                    if "Completed" not in eventItems['Description']: 
                                        orange_count += 1                                                                        
                                        result.append({'Instance ID':checkEvents['InstanceId'], 'Tag Name':tag_value, 'Event': eventItems['Code'], 'Description':eventItems['Description'], 
                                        'Scheduled Date':eventItems['NotBefore'].strftime('%m/%d/%Y')})
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                    grey_count += 1

                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                    green_count = total_count - orange_count 
                    
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Orange'], 'Result': result})
                    
                                    
            results['Details'] = details
            results['TotalCount'] = total_count
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'EC2Maintenance.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('EC2 Maintenance Events Check Finished')




