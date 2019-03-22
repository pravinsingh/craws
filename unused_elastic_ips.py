""" This rule checks for any unattached Elastic IPs currently available.
"""

__version__ = '0.6.1'
__author__ = 'Pravin Singh'

import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='UnusedElasticIps', level='DEBUG')
    logger.debug('Unused Elastic Ips check started')
    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/UnusedElasticIps.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Unused Elastic IPs'}
            results['Area'] = 'EC2'
            results['Description'] = 'Amazon Web Services enforce a small hourly charge if an Elastic IP (EIP) address within your ' +\
                'account is not associated with a running EC2 instance or an Elastic Network Interface (ENI). We recommend releasing ' +\
                'any unassociated EIPs that are no longer needed to reduce your AWS monthly costs.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='UnusedElasticIps')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    response = ec2_client.describe_addresses()
                    for address in response['Addresses']:
                        if 'AssociationId' in address:
                            green_count += 1
                        else:
                            name = ''
                            if 'Tags' in address:
                                for tag in address['Tags']:
                                    if tag['Key'] == 'Name':
                                        name = tag['Value']
                                        break

                            address['PublicIp'] = craws.get_cloudtrail_data(lookup_value=address['PublicIp'], 
                                            cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                            result.append({'Elastic IP':address['PublicIp'], 'Name':name})
                            yellow_count += 1
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
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Yellow'], 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'UnusedElasticIps.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Unused Elastic Ips check finished')

