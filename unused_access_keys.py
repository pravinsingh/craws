""" This rule checks users having Unused access/secret keys.
"""

__version__ = '0.1.0'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime



def handler(event, context):
    logger = craws.get_logger(name='UnusedAccessKeys')
    logger.debug('Unused Access Keys check started')

    sts = boto3.client('sts')

    for role_arn in craws.role_arns:
        results = {'Rule Name': 'Unused Access Keys'}
        results['Area'] = 'IAM'
        results['Description'] = 'Auditing all IAM users access/secret keys is a good way in order to secure the AWS account against' +\
            ' attackers. This rule will keep a check on all users unused,' +\
            'access/secret keys .'
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='UnusedKeys')
        except Exception as e:
            logger.error(e)
            continue
        credentials = response['Credentials']
        # We need to get the sts client again, with the temp tokens. Otherwise any attempt to get the account id 
        # will return the account id of the original caller and not the account id of the assumed role.
        sts_client = boto3.client('sts', aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
        account_id = sts_client.get_caller_identity().get('Account')
        #regions = craws.get_region_descriptions()
        #total_count = len(regions)
        green_count = red_count = orange_count = yellow_count = grey_count = 0
        
        KEY = 'LastUsedDate'
        
        iam_client = boto3.client('iam',
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
        iam = boto3.resource('iam',
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
        
        AccessId = None
        
        try:
            
            
            for user in iam.users.all():
                count = 0
                key_present = 0
                
                try:
                    result = []
                    for access_key in user.access_keys.all():
                        AccessId = access_key.access_key_id
                        key_present = key_present + 1
                            
                        LastUsed = iam_client.get_access_key_last_used(AccessKeyId=AccessId)
                        if KEY in LastUsed['AccessKeyLastUsed']:
                            last_used=LastUsed['AccessKeyLastUsed']['LastUsedDate']
                            last_used_date=last_used.date()
                            timeLimit1 = datetime.datetime.now() - datetime.timedelta(days=90)
                            three_month_before = timeLimit1.date()
                            if last_used_date < three_month_before:
                                count = count + 1
                                
                                
                                    
                                
                            
                    if count >= 1 and key_present >= 1:
                        details.append({'User Name': user.name,'ARN': user.arn, 'Status': craws.status['Red']})
                        red_count += 1
                
                    elif count == 0 and key_present >= 1 :
                        details.append({'User Name':user.name,'ARN': user.arn, 'Status': craws.status['Green']})
                        green_count += 1
                    
                    elif count == 0 and key_present == 0 :
                        details.append({'User Name':user.name,'ARN': user.arn, 'Status': craws.status['Grey']})
                        grey_count += 1
                                    
                            
                               
                
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'User Name': user.name, 'Status': craws.status['Grey']})
                    grey_count += 1
                        
        
        except Exception as e:
            logger.error(e)
            details.append({'Details': e, 'Status': craws.status['Grey']})
            grey_count += 1

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'UnusedAccessKeys.json', account_id)
        logger.info('Results for accout %s uploaded to s3', account_id)
    
    logger.debug('Unused Access Keys check finished')