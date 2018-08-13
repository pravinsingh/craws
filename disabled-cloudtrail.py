""" This rule checks whether CloudTrail is enabled for all regions.
"""

__version__ = '0.1.1'
__author__ = 'Biswa Singh'

import boto3
import craws


def handler(event, context):
    logger = craws.get_logger(name='DisbledCloudTrail', level='DEBUG')
    logger.debug('Disabled CloudTrail check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        results = {'Rule Name': 'Disabled CloudTrail'}
        results['Area'] = 'CloudTrail'
        results['Description'] = 'Amazon Web Services provides CloudTrail service to log all activities carried out from AWS console or CLI. ' +\
            'It is highly recommended to enable CloudTrail for all regions.'
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
                trails = clooudtrail_client.describe_trails()

                found = False

                for trail in trails['trailList']:
                    if trail['IsMultiRegionTrail'] == True or region['Id'] == trail['HomeRegion']:
                        found = True
                        break

                if found == True:
                    green_count += 1
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green']})
                else:
                    red_count += 1
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red']})

            except Exception as e:
                logger.error(e)
                grey_count += 1
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey']})

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'DisabledCloudTrail.json', account['account_id'])

    logger.debug('Disabled CloudTrail check finished')
