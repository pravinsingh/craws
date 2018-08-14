""" This rule checks whether users did not rotate their access/secret keys.
"""

__version__ = '0.1.2'
__author__ = 'Anmol Saini'

import boto3
import craws
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='KeysNotRotated')
    logger.debug('Keys Not Rotated check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        results = {'Rule Name': 'Access Keys Not Rotated'}
        results['Area'] = 'IAM'
        results[
            'Description'] = 'Auditing all IAM users access/secret keys is a good way to secure the AWS account against' + \
                             ' attackers. This rule will keep a check whether all users&#39; rotate their ' + \
                             'access/secret keys monthly.'
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='KeysNotRotated')
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
        AccessId = None

        for user in iam.users.all():
            try:
                count = 0
                result = []
                if iam_client.get_login_profile(UserName=user.name):
                    
                    for access_key in user.access_keys.all():
                        try:
                                AccessId = access_key.access_key_id
                                created_date = access_key.create_date.date()
                                timeLimit2 = datetime.datetime.now() - datetime.timedelta(days=30)
                                one_month_before = timeLimit2.date()
                                if created_date < one_month_before:
                                    count = count + 1

                        except Exception as e:
                            logger.error(e)
                        #   Exception occured, mark it as Grey (not checked)
                            details.append({'User Name': user.name, 'ARN': user.arn, 'Status': craws.status['Grey']})
                            grey_count += 1


                    if count >= 1:
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
        craws.upload_result_json(results, 'KeysNotRotated.json', account['account_id'])
        logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Keys Not Rotated check finished')
