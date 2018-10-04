""" This rule checks whether CloudTrail is logging successfully in all regions.
"""

__version__ = '0.3.1'
__author__ = 'Biswa Singh'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='CloudTrailLoggingStatus', level='DEBUG')
    logger.debug('CloudTrail Logging Status Check started')
    
    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/CloudTrailLoggingStatus.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'CloudTrail Logging Status'}
            results['Area'] = 'CloudTrail'
            results['Description'] = 'Amazon Web Services provides CloudTrail service to log all activities carried out from AWS console or CLI. ' +\
                'It is highly recommended to enable CloudTrail for all regions. This rule check cloudtrail logging status '
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='DisbledCloudTrail')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0
            
            for region in regions:
                clooudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                                    aws_access_key_id=credentials['AccessKeyId'],
                                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                                    aws_session_token=credentials['SessionToken'])
                try:
                    trails = clooudtrail_client.describe_trails(includeShadowTrails=False)
                    
                    for trail in trails['trailList']:
                        response = clooudtrail_client.get_trail_status(Name=trail['Name'])
                        if response['IsLogging'] == True:
                            #print(region['Id'] + '  ' + trail['Name'])
                            green_count += 1
                            details.append({'Status': craws.status['Green'], 'CloudTrailName':trail['Name'], 'Logging':response['IsLogging'], 'Region': region['Id'] + " (" + region['ShortName'] + ")"})
                        else:
                            red_count +=1
                            details.append({'Status': craws.status['Green'], 'CloudTrailName':trail['Name'], 'Logging':response['IsLogging'], 'Region': region['Id'] + " (" + region['ShortName'] + ")"})
                except Exception as e:
                    logger.error(e)
                
            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'CloudTrailLoggingStatus.json', account['account_id'])
        
    logger.debug('CloudTrail Logging Status finished')