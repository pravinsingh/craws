""" This rule checks for any unattached Elastic IPs currently available.
"""

__version__ = '0.1.0'
__author__ = 'Pravin Singh'

import boto3
import craws


def handler(event, context):
    logger = craws.get_logger(name='UnusedElasticIps', level='DEBUG')
    logger.debug('Unused Elastic Ips check started')
    sts = boto3.client('sts')

    for role_arn in craws.role_arns:
        results = {'Rule Name': 'Unused Elastic IPs'}
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='UnusedElasticIps')
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
        total_count = len(regions)
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        for region in regions:
            ec2_client = boto3.client('ec2', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            try:
                result = []
                response = ec2_client.describe_addresses()
                for address in response['Addresses']:
                    if 'AssociationId' not in address:
                        name = ''
                        if 'Tags' in address:
                            for tag in address['Tags']:
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break

                        result.append({'Elastic IP':address['PublicIp'], 'Name':name})
            except Exception as e:
                logger.error(e.message)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                grey_count += 1

            if len(result) == 0:
                # All good, mark it as Green
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                green_count += 1
            else:
                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Yellow'], 'Result': result})
                yellow_count += 1

        results['Details'] = details
        results['TotalCount'] = total_count
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'UnusedElasticIps.json', account_id)
        logger.info('Results for accout %s uploaded to s3', account_id)

    logger.debug('Unused Elastic Ips check finished')

handler(None, None)
        

