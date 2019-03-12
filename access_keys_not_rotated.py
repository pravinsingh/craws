""" This rule checks whether users did not rotate their access/secret keys.
"""

__version__ = '0.2.2'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='KeysNotRotated', level='DEBUG')
    logger.debug('Keys Not Rotated check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/KeysNotRotated.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Access Keys Not Rotated'}
            results['Area'] = 'IAM'
            results['Description'] = 'Auditing all IAM user access/secret keys is a good way to secure the AWS account ' + \
                                'against attackers. This rule will keep a check whether all the users rotate their ' + \
                                'access/secret keys monthly.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='KeysNotRotated')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0
    
            iam_client = boto3.client('iam',
                                aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'])
            iam_resource = boto3.resource('iam',
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
                    if iam_client.get_login_profile(UserName=user.name):
                        for access_key in user.access_keys.all():
                            created_date = access_key.create_date.date()
                            timeLimit2 = datetime.datetime.now() - datetime.timedelta(days=30)
                            one_month_before = timeLimit2.date()
                            if created_date < one_month_before:
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
            craws.upload_result_json(results, 'KeysNotRotated.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

        logger.debug('Keys Not Rotated check finished')
