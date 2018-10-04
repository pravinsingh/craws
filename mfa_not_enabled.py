""" This rule checks whether MFA (Multi Factor Authentication) is enabled for all IAM users as well as the root account.
"""

__version__ = '0.5.1'
__author__ = 'Pravin Singh'

import boto3
import craws
import csv
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='MfaNotEnabled')
    logger.debug('MFA Not Enabled check started')

    sts = boto3.client('sts')

    # Loop through all accounts
    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/MfaNotEnabled.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'MFA Not Enabled'}
            results['Area'] = 'IAM'
            results['Description'] = 'Having MFA-protected IAM users is the best way to protect your AWS resources and services against' +\
                ' attackers. An MFA device signature adds an extra layer of protection on top of your existing IAM user credentials.' +\
                ' NOTE: This rule only validates MFA for console users, it does not validate the non-console users (e.g. SES users).'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='MfaNotEnabled')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            iam_client = boto3.client('iam', 
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            try:
                while (iam_client.generate_credential_report()['State'] != 'COMPLETE'):
                    time.sleep(1)
                response = iam_client.get_credential_report()
                report_csv = response['Content'].decode()
                reader = csv.DictReader(report_csv.splitlines())
                for row in reader:
                    try:
                        if row['user'] == '<root_account>':
                            row['user'] = '&lt;root_account&gt;'
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        if row['mfa_active'] == 'false':
                            # Ignore the non-console users and show them as Grey
                            if row['password_enabled'] == 'false':
                                details.append({'User Name': row['user'], 'ARN': row['arn'], 'Status': craws.status['Grey']})
                                grey_count += 1
                            else:
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
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'MfaNotEnabled.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('MFA Not Enabled check finished')

