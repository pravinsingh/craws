""" This rule checks whether users have Unused access/secret keys.
"""

__version__ = '0.3.0'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='UnusedAccessKeys')
    logger.debug('Unused Access Keys check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/UnusedAccessKeys.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Unused Access Keys'}
            results['Area'] = 'IAM'
            results['Description'] = 'Auditing all IAM users&#39; access keys is a good way to secure the AWS account ' + \
                                    'against attacks. This rule will identify the access keys not used in the last 90 days.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='UnusedKeys')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0
            key = 'LastUsedDate'
            iam_resource = boto3.resource('iam',
                                    aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'])
            iam_client = boto3.client('iam',
                                    aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'])
            cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1',
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
    
            for user in iam_resource.users.all():
                try:
                    count = 0
                    for access_key in user.access_keys.all():
                        AccessId = access_key.access_key_id
                        LastUsed = iam_client.get_access_key_last_used(AccessKeyId=AccessId)
                        if key in LastUsed['AccessKeyLastUsed']:
                            last_used = LastUsed['AccessKeyLastUsed']['LastUsedDate']
                            last_used_date = last_used.date()
                            timeLimit1 = datetime.datetime.now() - datetime.timedelta(days=90)
                            three_month_before = timeLimit1.date()
                            if last_used_date < three_month_before:
                                count += 1
    
                    if count >= 1:
                        username = craws.get_cloudtrail_data(lookup_value=user.name, cloudtrail_client=cloudtrail_client)
                        details.append({'Status': craws.status['Red'], 'User Name': username, 'ARN': user.arn})
                        red_count += 1
                    else:
                        username = craws.get_cloudtrail_data(lookup_value=user.name, cloudtrail_client=cloudtrail_client)
                        details.append({'Status': craws.status['Green'], 'User Name': username, 'ARN': user.arn})
                        green_count += 1
                except Exception as e:
                    logger.error(e)
                    username = craws.get_cloudtrail_data(lookup_value=user.name, cloudtrail_client=cloudtrail_client)
                    details.append({'Status': craws.status['Grey'], 'User Name': username, 'ARN': user.arn})
                    grey_count += 1
    
            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'UnusedAccessKeys.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Unused Access Keys check finished')
