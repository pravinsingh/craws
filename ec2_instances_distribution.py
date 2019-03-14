""" This rule ensures that the EC2 instances are evenly spread across all Availability Zones (AZs) within an AWS region.
"""

__version__ = '0.4.2'
__author__ = 'Pravin Singh'

import boto3
import craws
import math
import datetime

def standard_deviation(values):
    mean = float(sum(values)) / max(len(values), 1)
    diff_sq = []
    for v in values:
        diff_sq.append((v - mean)**2)
    variance = sum(diff_sq) / max(len(diff_sq), 1)
    sd = math.sqrt(variance)
    return sd

def handler(event, context):
    logger = craws.get_logger(name='Ec2InstancesDistribution', level='DEBUG')
    logger.debug('Ec2 Instances Distribution check started')
    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/Ec2InstancesDistribution.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'EC2 Instances Not Distributed Evenly Across AZs'}
            results['Area'] = 'EC2'
            results['Description'] = 'Having a balanced distribution of EC2 instances across all Availability Zones in a region will improve the' +\
                ' availability and reliability of your applications in case of an AWS planned or unplanned service disruption.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='Ec2InstancesDistribution')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            total_count = len(regions)
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    response = ec2_client.describe_availability_zones()
                    zones = response['AvailabilityZones']
                    az_instance_count = {}
                    for zone in zones:
                        az_instance_count[zone['ZoneName']]=0
                    response = ec2_client.describe_instances()
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            az_instance_count[instance['Placement']['AvailabilityZone']] = \
                                            az_instance_count[instance['Placement']['AvailabilityZone']] + 1
                    values = az_instance_count.values()
                    total_instances = sum(values)
                    mean = float(total_instances) / max(len(values), 1) 
                    # Uneven distribution does not matter much if there are less than 10 total instances 
                    if total_instances > 10:
                        # Calculate the standard deviation and coefficient of variation (%)
                        sd = standard_deviation(values)
                        coeff_var = sd * 100 / mean
                        if coeff_var > 50:
                            for az in az_instance_count:
                                result.append({'Availability Zone': az, 'Total Instances': az_instance_count[az]})

                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                    grey_count += 1

                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                    green_count += 1
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Orange'], 'Result': result})
                    orange_count += 1

            results['Details'] = details
            results['TotalCount'] = total_count
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'Ec2InstancesDistribution.json', account['account_id'])
            logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('Ec2 Instances Distribution check finished')

