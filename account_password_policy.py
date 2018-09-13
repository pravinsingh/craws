""" This rule checks the aws account password policy"
"""

__version__ = '0.4.1'
__author__ = 'Bhupender Kumar'

import boto3
import craws
import csv
import time
import datetime

def handler(event, context):
    logger = craws.get_logger(name='PasswordPolicy', level='DEBUG')
    logger.debug('Password policy check started')

    sts = boto3.client('sts')

    # Loop through all accounts
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/AccountPasswordPolicy.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Account Password Policy'}
            results['Area'] = 'IAM'
            results['Description'] = 'Enforcing AWS IAM passwords strength, pattern and rotation is vital when it comes to maintaining the security of your AWS account.' +\
                'Having a strong password policy in use will significantly reduce the risk of' +\
                ' password-guessing and brute-force attacks.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='AccountPasswordPolicy')
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
                result = []
                response = iam_client.get_account_password_policy()
                if bool(response['PasswordPolicy']) == False:
                    details.append({'Status': craws.status['Red'], 'Policy Detail': "Password policy set for the account"})
                    red_count += 1
                else:
                    green_count += 1
                    details.append({'Policy Detail': "Password policy set for the account", 'Status': craws.status['Green']})
                    if 'MinimumPasswordLength' in response['PasswordPolicy'].keys():
                        if response['PasswordPolicy']['MinimumPasswordLength'] >=8:
                            green_count += 1
                            details.append({'Status': craws.status['Green'], 'Policy Detail': "Minimum password length should be more than 8 characters"})
                        else:
                            red_count += 1
                            details.append({'Status': craws.status['Red'], 'Policy Detail': "Minimum password length should be more than 8 characters"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Minimum password length should be more than 8 characters"})
                    if 'MaxPasswordAge' in response['PasswordPolicy'].keys():
                        if response['PasswordPolicy']['MaxPasswordAge'] <= 90:
                            green_count += 1
                            details.append({'Status': craws.status['Green'], 'Policy Detail': "Maximum password age should be less than 90 days"})
                        else:
                            red_count += 1
                            details.append({'Status': craws.status['Red'], 'Policy Detail': "Maximum password age should be less than 90 days"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Maximum password age should be less than 90 days"})
                    if 'PasswordReusePrevention' in response['PasswordPolicy'].keys():
                        if response['PasswordPolicy']['PasswordReusePrevention'] >= 10:
                            green_count += 1
                            details.append({'Status': craws.status['Green'], 'Policy Detail': "Password reuse prevention should be more than 10 times"})
                        else:
                            red_count += 1
                            details.append({'Status': craws.status['Red'], 'Policy Detail': "Password reuse prevention should be more than 10 times"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Password reuse prevention should be more than 10 times"})
                    if response['PasswordPolicy']['RequireSymbols'] == True:
                        green_count += 1
                        details.append({'Status': craws.status['Green'], 'Policy Detail': "Password should require atleast one special character"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Password should require atleast one special character"})
                    if response['PasswordPolicy']['RequireNumbers'] == True:
                        green_count += 1
                        details.append({'Status': craws.status['Green'], 'Policy Detail': "Password should require atleast one number"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Password should require atleast one number"})
                    if response['PasswordPolicy']['RequireUppercaseCharacters'] == True:
                        green_count += 1
                        details.append({'Status': craws.status['Green'], 'Policy Detail': "Password should require atleast one uppercase character"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Password should require atleast one uppercase character"})
                    if response['PasswordPolicy']['RequireLowercaseCharacters'] == True:
                        green_count += 1
                        details.append({'Status': craws.status['Green'], 'Policy Detail': "Password should require atleast one lowercase character"})
                    else:
                        red_count += 1
                        details.append({'Status': craws.status['Red'], 'Policy Detail': "Password should require atleast one lowercase character"})

        
            except Exception as e:
                logger.error(e)
                details.append({'Status': craws.status['Grey'], 'Details': e})
                grey_count += 1

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'AccountPasswordPolicy.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

        logger.debug('Password policy check started')