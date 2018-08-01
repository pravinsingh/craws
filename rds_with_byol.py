""" This rule checks for any RDS Instances with BYOL License Model.
"""

__version__ = '0.3.1'
__author__ = 'Pravin Singh'

import boto3
import craws


def handler(event, context):
    logger = craws.get_logger(name='RdsWithBYOL')
    logger.debug('Rds With BYOL check started')

    sts = boto3.client('sts')

    for role_arn in craws.role_arns:
        results = {'Rule Name': 'RDS Instances with BYOL License Model'}
        results['Area'] = 'RDS'
        results['Description'] = 'Identify any Oracle RDS instances configured with Bring-Your-Own-License (BYOL) license model. ' +\
            'We should always create Oracle RDS instances with License-Attached license model.'
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='RdsWithBYOL')
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
                details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                grey_count += 1

            if len(result) == 0:
                # All good, mark it as Green
                details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
            else:
                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                details.append({'Status': craws.status['Red'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'RdsWithBYOL.json', account_id)
        logger.info('Results for accout %s uploaded to s3', account_id)

    logger.debug('Rds With BYOL check finished')
