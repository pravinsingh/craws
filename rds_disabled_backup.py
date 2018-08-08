""" This rule checks for any RDS Instances with Disabled Automated Backup.
"""

__version__ = '0.1.0'
__author__ = 'Anmol Saini'

import boto3
import craws


def handler(event, context):
    logger = craws.get_logger(name='RdsWithDisabledBackup')
    logger.debug('Rds With Disabled backup check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        results = {'Rule Name': 'RDS Instances with Disabled Automated Backup'}
        results['Area'] = 'RDS'
        results['Description'] = 'Ensure that no AWS RDS database instances has automated backup '  +\
            'disabled .'
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
            try:
                result = []
                response = rds_client.describe_db_instances()
                for instance in response['DBInstances']:
                    if instance['BackupRetentionPeriod'] == 0:
                        result.append({'Instance ID':instance['DBInstanceIdentifier'], 'Name':instance['DBName'],
                            'Engine':instance['Engine'], 'Master Username':instance['MasterUsername']})
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                grey_count += 1

            if len(result) == 0:
                # All good, mark it as Green
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                green_count += 1
            else:
                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})
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

