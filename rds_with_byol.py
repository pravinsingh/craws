""" This rule checks for any RDS Instances with BYOL License Model.
"""

__version__ = '0.5.0'
__author__ = 'Pravin Singh'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='RdsWithBYOL')
    logger.debug('Rds With BYOL check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/RdsWithBYOL.json')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'RDS Instances with BYOL License Model'}
            results['Area'] = 'RDS'
            results['Description'] = 'Identify any Oracle RDS instances configured with Bring-Your-Own-License (BYOL) license model. ' +\
                'We should always create Oracle RDS instances with License-Attached license model.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='RdsWithBYOL')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                rds_client = boto3.client('rds', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    response = rds_client.describe_db_instances()
                    for instance in response['DBInstances']:
                        if instance['LicenseModel'] is 'bring-your-own-license':
                            result.append({'Instance ID':instance['DBInstanceIdentifier'], 'Name':instance['DBName'],
                                'Engine':instance['Engine'], 'Master Username':instance['MasterUsername']})
                            orange_count += 1
                        else:
                            green_count += 1
                            
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                    grey_count += 1

                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'RdsWithBYOL.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Rds With BYOL check finished')

