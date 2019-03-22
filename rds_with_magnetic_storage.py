""" This rule checks for any RDS Instances with Magnetic Storage Type.
"""

__version__ = '0.2.1'
__author__ = 'Bhupender Kumar'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='RdsWithMagneticStorage', level='DEBUG')
    logger.debug('Rds With Magnetic Storage check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/RdsWithMagneticStorage.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'RDS Instances with Magnetic Storage Type'}
            results['Area'] = 'RDS'
            results['Description'] = 'Identify any RDS instances configured with Magnetic Storage Type. ' +\
                                    'We should always create RDS instances with General Purpose SSD or Provisioned IOPS SSD.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='RdsWithMagneticStorage')
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
                        try:
                            if instance['StorageType'] == 'standard':
                                instance_id = craws.get_cloudtrail_data(lookup_value=instance['DBInstanceIdentifier'], 
                                    cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                result.append({'DBInstance ID':instance_id, 'Engine':instance['Engine'], 'Storage Type': instance['StorageType']})
                                red_count += 1
                            else:
                                green_count += 1
                        except:
                            instance_id = craws.get_cloudtrail_data(lookup_value=instance['DBInstanceIdentifier'], 
                                    cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                            result.append({'DBInstance ID':instance_id, 'Engine':instance['Engine'], 'Storage Type': "Not Checked. Please verify."})
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'],'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1

                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'],'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Status': craws.status['Red'],'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'RdsWithMagneticStorage.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Rds With Magnetic Storage check finished')