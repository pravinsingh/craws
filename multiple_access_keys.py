""" This rule checks whether user having multiple access/secret keys.
"""

__version__ = '0.1.1'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='MultipleAccessKeys')
    logger.debug('Multiple Access Keys check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        results = {'Rule Name': 'Multiple Access Keys'}
        results['Area'] = 'IAM'
        results[
            'Description'] = 'Auditing all IAM users access/secret keys is a good way to secure the AWS account against' + \
                             ' attackers. This rule will keep a check on all users having multiple ' + \
                             'access/secret keys .'
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='MultipleKeys')
        except Exception as e:
            logger.error(e)
            continue
        credentials = response['Credentials']
        regions = craws.get_region_descriptions()
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        iam_client = boto3.client('iam',
                                  aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'],
                                  aws_session_token=credentials['SessionToken'])
        iam = boto3.resource('iam',
                             aws_access_key_id=credentials['AccessKeyId'],
                             aws_secret_access_key=credentials['SecretAccessKey'],
                             aws_session_token=credentials['SessionToken'])

        for user in iam.users.all():

            try:

                count = 0
                result = []

                for access_key in user.access_keys.all():
                    try:
                        count = count + 1


                    except Exception as e:
                        logger.error(e)
                        details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Grey']})
                        grey_count += 1

                if count > 1:
                    details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Red']})
                    red_count += 1

                else:
                    details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Green']})
                    green_count += 1

            except Exception as e:
                logger.error(e)
                details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Grey']})
                grey_count += 1

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'MultipleAccessKeys.json', account['account_id'])
        logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Multiple Access Keys check finished')