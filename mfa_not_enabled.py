""" This rule checks whether MFA (Multi Factor Authentication) is enabled for all IAM users as well as the root account.
"""

__version__ = '0.1.0'
__author__ = 'Pravin Singh'

import boto3
import craws
import csv
import time

def handler(event, context):
    logger = craws.get_logger(name='MfaNotEnabled')
    logger.debug('MFA Not Enabled check started')

    sts = boto3.client('sts')

    # Loop through all accounts
    for role_arn in craws.role_arns:
        results = {'Rule Name': 'MFA Not Enabled for all IAM users'}
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='MfaNotEnabled')
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
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        iam_client = boto3.client('iam', 
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
        try:
            response = iam_client.generate_credential_report()
            while (response['State'] != 'COMPLETE'):
                time.sleep(1)
            response = iam_client.get_credential_report()
            report_csv = response['Content']
            reader = csv.DictReader(report_csv.splitlines())
            total_count = 0
            for row in reader:
                try:
                    total_count += 1
                    if row['user'] == '<root_account>':
                        row['user'] = '&lt;root_account&gt;'
                    if row['mfa_active'] == 'false':
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'User Name': row['user'], 'ARN': row['arn'], 'Status': craws.status['Red']})
                        red_count += 1
                    else:
                        # All good, mark it as Green
                        details.append({'User Name': row['user'], 'ARN': row['arn'], 'Status': craws.status['Green']})
                        green_count += 1
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'User Name': row['user'], 'ARN': row['arn'], 'Status': craws.status['Grey']})
                    grey_count += 1
        except Exception as e:
            logger.error(e)
            details.append({'Details': e, 'Status': craws.status['Grey']})
            grey_count += 1

        results['Details'] = details
        results['TotalCount'] = total_count
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'MfaNotEnabled.json', account_id)
        logger.info('Results for accout %s uploaded to s3', account_id)

    logger.debug('MFA Not Enabled check finished')

handler(None, None)