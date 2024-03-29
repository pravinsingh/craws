""" This rule checks for s3 buckets with 'WRITE' access open to everyone.
"""

__version__ = '0.3.1'
__author__ = 'Pravin Singh'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='S3PublicWrite', level='DEBUG')
    logger.debug('S3 Public Write check started')
    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/S3PublicWrite.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'S3 Bucket Public WRITE Access'}
            results['Area'] = 'S3'
            results['Description'] = 'Granting public &#39;WRITE&#39; access to your AWS S3 buckets can allow anonymous users to upload,' +\
                                    ' modify and delete S3 objects without permission.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='S3PublicWrite')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            s3_client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                try:
                    bucket_location = s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                    cloudtrail_client = boto3.client('cloudtrail', region_name=bucket_location,
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                    found = False
                    response = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                    for grant in response['Grants']:
                        if ('URI' in grant['Grantee']
                                    and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers'
                                    and (grant['Permission'] == 'WRITE' or grant['Permission'] == 'FULL_CONTROL')):
                            found = True
                            break
                    bucket['Name'] = craws.get_cloudtrail_data(lookup_value=bucket['Name'], 
                                    cloudtrail_client=cloudtrail_client, region_id=bucket_location)
                    if found == True:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Red'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                        red_count += 1
                    else:
                        # All good, mark it as Green
                        details.append({'Status': craws.status['Green'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                        green_count += 1
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                    grey_count += 1

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'S3PublicWrite.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('S3 Public Write check finished')

