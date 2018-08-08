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
                details.append({'Password Policy': "Not Set", 'Reason': "Password policy is not defined", 'Status': craws.status['Red']})
                red_count += 1
            else:
                if 'MinimumPasswordLength' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['MinimumPasswordLength'] >=8:
                        green_count += 1
                        pass
                    else:
                        red_count += 1
                        details.append({'Password Policy': "Weak", 'Reason': "Minimum password length is less than 8 characters", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Minimum password length is not set", 'Status': craws.status['Red']})
                if 'MaxPasswordAge' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['MaxPasswordAge'] <= 90:
                        green_count += 1
                        pass
                    else:
                        red_count += 1
                        details.append({'Password Policy': "Weak", 'Reason': "Max password age is less than 90 days", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Max password age is not set", 'Status': craws.status['Red']})
                if 'PasswordReusePrevention' in response['PasswordPolicy'].keys():
                    if response['PasswordPolicy']['PasswordReusePrevention'] >= 20:
                        green_count += 1
                        pass
                    else:
                        red_count += 1
                        details.append({'Password Policy': "Weak", 'Reason': "Password reuse prevention is less than 20 times", 'Status': craws.status['Red']})
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Password reuse prevention is not set", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireSymbols'] == True:
                    green_count += 1
                    pass
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Password does not require symbol", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireNumbers'] == True:
                    green_count += 1
                    pass
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Password does not require numbers", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireUppercaseCharacters'] == True:
                    green_count += 1
                    pass
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Password does not require uppercase characters", 'Status': craws.status['Red']})
                if response['PasswordPolicy']['RequireLowercaseCharacters'] == True:
                    green_count += 1
                    pass
                else:
                    red_count += 1
                    details.append({'Password Policy': "Weak", 'Reason': "Password does not require lowercase characters", 'Status': craws.status['Red']})
                
            if len(details) == 0:
                green_count += 1
                details.append({'Password Policy': "Strong", 'Reason': "All parameters for strong password are set", 'Status': craws.status['Green']})
                # All good, mark it as Green
                #details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})

        
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
