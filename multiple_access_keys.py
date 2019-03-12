""" This rule checks whether user having multiple access/secret keys.
"""

__version__ = '0.3.0'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='MultipleAccessKeys')
    logger.debug('Multiple Access Keys check started')

    sts = boto3.client('sts')

    # Loop through all accounts
    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/MultipleAccessKeys.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Multiple Access Keys'}
            results['Area'] = 'IAM'
            results['Description'] = 'AWS allows you to assign maximum two active access keys but this is recommended only ' + \
                                    'during the key rotation process. We strongly recommend deactivating the old key once ' + \
                                    'the new one is created so only one access key will remain active for the IAM user.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='MultipleKeys')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0

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
                    for access_key in user.access_keys.all():
                        count += 1

                    if count > 1:
                        details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Red']})
                        red_count += 1
                    else:
                        username = craws.get_cloudtrail_data(lookup_value=user.name, cloudtrail_client=cloudtrail_client)
                        details.append({'User Name': username, 'ARN': user.arn, 'Status': craws.status['Green']})
                        green_count += 1

                except Exception as e:
                    logger.error(e)
                    username = craws.get_cloudtrail_data(lookup_value=user.name, cloudtrail_client=cloudtrail_client)
                    details.append({'User Name': username, 'ARN': user.arn, 'Status': craws.status['Grey']})
                    grey_count += 1

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'MultipleAccessKeys.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Multiple Access Keys check finished')
