""" This rule checks whether RDS instances have disabled automated backup.
"""

__version__ = '0.3.0'
__author__ = 'Anmol Saini'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='RdsWithDisabledBackup')
    logger.debug('Rds With Disabled backup check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/RdsWithDisabledBackup.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'RDS Instances With Disabled Automated Backup'}
            results['Area'] = 'RDS'
            results['Description'] = 'Ensure that your RDS database instances have automated backups enabled, for point-in-time recovery. ' +\
                                    'To back up your database instances, AWS RDS automatically takes a full daily snapshot of your data ' +\
                                    '(with transactions logs) and keeps the backups for a limited period of time. These snapshots will ' +\
                                    'allow you to handle data restoration efficiently in the event of a user error on the source database.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='RdsWithNoBackup')
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
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    response = rds_client.describe_db_instances()
                    for instance in response['DBInstances']:
                        if instance['BackupRetentionPeriod'] == 0:
                            instance['DBInstanceIdentifier'] = craws.get_cloudtrail_data(lookup_value=instance['DBInstanceIdentifier'], cloudtrail_client=cloudtrail_client)
                            result.append({'Instance ID':instance['DBInstanceIdentifier'], 'Name':instance['DBName'],
                                'Engine':instance['Engine'], 'Master Username':instance['MasterUsername']})
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
    
                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    green_count += 1
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Status': craws.status['Red'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    red_count += 1
    
            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'RdsWithDisabledBackup.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Rds With Disabled Backup check finished')

