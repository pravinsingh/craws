""" This rule checks for certificate expiry.
"""

__version__ = '0.1.0'
__author__ = 'Govarthanan Rajappan'

import craws
import os
import boto3
import json
import datetime

def handler(event, context):
    
    logger = craws.get_logger(name='CertificateExpiry')
    logger.debug('ACM Certificate Expiry check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/AcmCertificateExpiry.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            results = {'Rule Name': 'Expiring/Expired ACM Certificates'}
            results['Area'] = 'ACM'
            results['Description'] = 'This checks shows certificates going to expire in next 30 days(red) as well as the ones that are alerady expired(orange).' +\
                                     'Total items represents the total certificates in all regions.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='CertificateExpiry')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0
            
            
            for region in regions:
                #print (region['Id'])
                red_bool = orange_bool = False
                region_red_count = region_orange_count = region_grey_count = region_green_count = 0
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                try:
                    result = []            
                    daysToCheck = 30
                    acm_client = boto3.client('acm',region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                    certs = acm_client.list_certificates()
                    for id, val in certs.items():
                        if id == "CertificateSummaryList":
                            for i in val:
                                for j, k in i.items():
                                    if j == "CertificateArn":
                                        cert = acm_client.describe_certificate(CertificateArn=k)
                                        for l, m in cert.items():
                                            if l == "Certificate":
                                                for n, o in m.items():
                                                    if n == "DomainName":
                                                        DomainName = o
                                                    if n == "NotAfter":
                                                        ExpirationDate = o
                                                        margin = datetime.timedelta(days = daysToCheck)
                                                        today = datetime.date.today()
                                                        if (today <= o.date() <= today + margin):
                                                            result.append({'CertificateArn': k, 'Domain Name': DomainName, 'Expiration': str(o)})
                                                            red_count += 1
                                                            region_red_count += 1
                                                            red_bool = True
                                                        elif (o.date() < today):
                                                            result.append({'CertificateArn': k, 'Domain Name': DomainName, 'Expiration': str(o)})
                                                            orange_count += 1
                                                            region_orange_count += 1
                                                            orange_bool = True
                                                        else:
                                                            green_count += 1
                                                            region_green_count += 1
                                                            # All good, mark it as Green
                except Exception as e:
                    print (e)
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
                
                if region_red_count > region_orange_count:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Red'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                elif region_orange_count > region_green_count:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Orange'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                else:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'AcmCertificateExpiry.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])
    logger.debug('ACM Certificate Expiry check finished')
