""" This rule checks for iam certificate expiry.
"""

__version__ = '0.1.0'
__author__ = 'Govarthanan Rajappan'

import craws
import os
import boto3
import json
import datetime

def handler(event, context):
    
    logger = craws.get_logger(name='IamCertificateExpiry')
    logger.debug('IAM Certificate Expiry check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/IamCertificateExpiry.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            results = {'Rule Name': 'Expiring/Expired IAM Certificates'}
            results['Area'] = 'IAM'
            results['Description'] = 'This checks shows certificates going to expire in next 30 days(red) as well as the ones that are alerady expired(orange).' +\
                                     'Total items represents the total certificates in all regions.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='CertificateExpiry')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            green_count = red_count = orange_count = yellow_count = grey_count = 0
            try:
                result = []            
                daysToCheck = 30
                iam_client = boto3.client('iam',
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
                certs = iam_client.list_server_certificates()
                for id, val in certs.items():
                    if id == "ServerCertificateMetadataList":
                        for i in val:
                            for j, k in i.items():
                                if j == "ServerCertificateName":
                                    CertName = k
                                if j == "Arn":
                                    CertARN = k
                                if j == "Expiration":
                                    ExpirationDate = k
                                    margin = datetime.timedelta(days = daysToCheck)
                                    today = datetime.date.today()
                                    if (k.date() < today):
                                        result.append({'Status': craws.status['Orange'], 'CertificateArn': CertARN, 'Cert Name': CertName, 'Expiration': str(ExpirationDate)})
                                        orange_count += 1
                                    elif (today - margin <= k.date() <= today + margin):
                                        result.append({'Status': craws.status['Red'], 'CertificateArn': CertARN, 'Cert Name': CertName, 'Expiration': str(ExpirationDate)})
                                        red_count += 1
                                    else:
                                        result.append({'Status': craws.status['Green'], 'CertificateArn': CertARN, 'Cert Name': CertName, 'Expiration': str(ExpirationDate)})
                                        green_count += 1
            except Exception as e:
                    print (e)
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Result': result})
                    grey_count += 1

            results['Details'] = result
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            #print(results)
            craws.upload_result_json(results, 'IamCertificateExpiry.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])
    logger.debug('IAM Certificate Expiry check finished')
