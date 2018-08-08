""" This rule checks the aws account password policy"
"""

__version__ = '0.2.0'
__author__ = 'Bhupender Kumar'

import boto3
import craws
import csv
import time

def handler(event, context):
    logger = craws.get_logger(name='PasswordPolicy')
    logger.debug('Password policy check started')

    sts = boto3.client('sts')

    # Loop through all accounts
    for account in craws.accounts:
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
                details.append({'Policy Detail': "Password policy set for the account", 'Status': craws.status['Red']})
                red_count += 1
            else:
                green_count += 1
                details.append({'Policy Detail': "Password policy set for the account", 'Status': craws.status['Green']})
                if 'MinimumPasswordLength' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['MinimumPasswordLength'] >=8:
                        green_count += 1
                        details.append({'Policy Detail': "Minimum password length should be more than 8 characters", 'Status': craws.status['Green']})
                    else:
                        red_count += 1
                        details.append({'Policy Detail': "Minimum password length should be more than 8 characters", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Minimum password length should be more than 8 characters", 'Status': craws.status['Red']})
                if 'MaxPasswordAge' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['MaxPasswordAge'] <= 90:
                        green_count += 1
                        details.append({'Policy Detail': "Maximum password age should be less than 90 days", 'Status': craws.status['Green']})
                    else:
                        red_count += 1
                        details.append({'Policy Detail': "Maximum password age should be less than 90 days", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Maximum password age should be less than 90 days", 'Status': craws.status['Red']})
                if 'PasswordReusePrevention' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['PasswordReusePrevention'] >= 10:
                        green_count += 1
                        details.append({'Policy Detail': "Password reuse prevention should be more than 10 times", 'Status': craws.status['Green']})
                    else:
                        red_count += 1
                        details.append({'Policy Detail': "Password reuse prevention should be more than 10 times", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Password reuse prevention should be more than 10 times", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireSymbols'] == True:
                    green_count += 1
                    details.append({'Policy Detail': "Password should require atleast one special character", 'Status': craws.status['Green']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Password should require atleast one special character", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireNumbers'] == True:
                    green_count += 1
                    details.append({'Policy Detail': "Password should require atleast one number", 'Status': craws.status['Green']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Password should require atleast one number", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireUppercaseCharacters'] == True:
                    green_count += 1
                    details.append({'Policy Detail': "Password should require atleast one uppercase character", 'Status': craws.status['Green']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Password should require atleast one uppercase character", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireLowercaseCharacters'] == True:
                    green_count += 1
                    details.append({'Policy Detail': "Password should require atleast one lowercase character", 'Status': craws.status['Green']})
                else:
                    red_count += 1
                    details.append({'Policy Detail': "Password should require atleast one lowercase character", 'Status': craws.status['Red']})

        
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
        craws.upload_result_json(results, 'AccountPasswordPolicy.json', account['account_id'])
        logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Password policy check started')
