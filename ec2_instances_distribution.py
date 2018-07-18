""" This rule ensures that the EC2 instances are evenly spread across all Availability Zones (AZs) within an AWS region.
"""

__version__ = '0.1.0'
__author__ = 'Pravin Singh'

import boto3
import craws
import math

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

    for role_arn in craws.role_arns:
        results = {'Rule Name': 'EC2 Instances not distributed evenly across availability zones'}
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='Ec2InstancesDistribution')
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
        regions = craws.get_region_descriptions()
        region_count = len(regions)
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
        results['RegionCount'] = region_count
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'Ec2InstancesDistribution.json', account_id)
        logger.info('Results for accout %s uploaded to s3', account_id)

    logger.debug('Ec2 Instances Distribution check finished')
