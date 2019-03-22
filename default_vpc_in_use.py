""" This rule checks for EC2 instances in default or no VPC.
"""

__version__ = '0.2.1'
__author__ = 'Bhupender Kumar'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='DefaultVpcInUse', level='DEBUG')
    logger.debug('Default VPC in Use check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/DefaultVpcInUse.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'EC2 Instances in Default or No VPC'}
            results['Area'] = 'EC2'
            results['Description'] = 'A default Virtual Private Cloud is designed in such a way that you can quickly deploy AWS resources and not '  +\
                                    'have to think about the underlying network. The default VPC comes with a default configuration that would not ' +\
                                    'meet all security best practices, hence a non-default VPC should be used for sophisticated AWS cloud applications.' 
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='DefaultVpcInUse')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                try:
                    default_vpc = ''
                    result = []
                    response = ec2_client.describe_vpcs()
                    for vpc_detail in response['Vpcs']:
                        if vpc_detail['IsDefault'] == True:
                            default_vpc = vpc_detail['VpcId']
                            
                    resp = ec2_client.describe_instances()
                    for ec2_instances in resp['Reservations']:
                        for instance_details in ec2_instances['Instances']:
                            try:
                                if instance_details['VpcId'] == default_vpc:
                                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                    orange_count += 1
                                    instance_details['InstanceId'] = craws.get_cloudtrail_data(lookup_value=instance_details['InstanceId'], 
                                            cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                    result.append({'VPC Id': default_vpc, 'Instance Id': instance_details['InstanceId']})
                                else:
                                    # All good, mark it as Green
                                    green_count += 1
                            except KeyError:
                                # Some issues found, No VPC found for the instance
                                orange_count += 1
                                result.append({'VPC Id': "No VPC Attached. Please try to upgrade.", 'Instance Id': instance_details['InstanceId']})
                except Exception as e:
                    # Exception occured, mark it as Grey (not checked)
                    logger.error(e)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
            
                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Status': craws.status['Orange'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'DefaultVpcInUse.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Default VPC in Use check finished')