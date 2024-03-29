""" This rule checks for any unused security groups in AWS account.
"""

__version__ = '0.8.0'
__author__ = 'Bhupender Kumar, Pravin Singh'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='UnusedSecurityGroups', level='DEBUG')
    logger.debug('Unused Security Groups check started')

    sts = boto3.client('sts')
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/UnusedSecurityGroups.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            logger.info('Starting Account ' + account['account_id'] + ' ...')
            results = {'Rule Name': 'Unused Custom Security Groups'}
            results['Area'] = 'EC2'
            results['Description'] = 'This rule checks the unused and dangling custom security groups in the AWS account. Security ' + \
                                 'groups that are not attached to any resource should be deleted to minimize the surface of attack.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='unused_security_group')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                logger.debug('REGION: ' + region['Id'])
                ec2_client = boto3.client('ec2', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    security_groups = ec2_client.describe_security_groups()
                    default_security_groups = set([security_group['GroupId'] \
                        for security_group in security_groups['SecurityGroups'] \
                            if security_group['GroupName'] == 'default'])
                    all_security_groups = set([security_group['GroupId'] for security_group in security_groups['SecurityGroups']])
                    custom_security_groups = set(all_security_groups - default_security_groups)
                    used_security_groups = set()

                    # Check if the security group is used in a network interface
                    net_interface = ec2_client.describe_network_interfaces()
                    for interface in net_interface['NetworkInterfaces']:
                        for group in interface['Groups']:
                            used_security_groups.add(group['GroupId'])

                    # Check if the security group is used in another security group's inbound rules
                    for security_group in security_groups['SecurityGroups']:
                        for IpPermission in security_group['IpPermissions']:
                            for UserIdGroupPair in IpPermission['UserIdGroupPairs']:
                                used_security_groups.add(UserIdGroupPair['GroupId'])

                    # Check if the security group is used in another security group's outbound rules
                    for security_group in security_groups['SecurityGroups']:
                        for IpPermission in security_group['IpPermissionsEgress']:
                            for UserIdGroupPair in IpPermission['UserIdGroupPairs']:
                                used_security_groups.add(UserIdGroupPair['GroupId'])
                    green_count += len(list(used_security_groups))

                    unused_security_groups = custom_security_groups - used_security_groups

                    for unused_security_group in list(unused_security_groups):
                        for security_group in security_groups['SecurityGroups']:
                            if security_group['GroupId'] == unused_security_group:
                                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                orange_count += 1

                                unused_security_group_data = craws.get_cloudtrail_data(lookup_value=unused_security_group,
                                                                   cloudtrail_client=cloudtrail_client,
                                                                   region_id=region['Id'])
                                result.append({'Security Group Id': unused_security_group_data,
                                        'Name': security_group['GroupName'],
                                        'VPC ID': security_group['VpcId'] if 'VpcId' in security_group else ''
                                })

                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append(
                        {'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")",
                         'Result': result})
                    grey_count += 1

                if len(result) == 0:
                    # All good, mark it as Green
                    # details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                    details.append(
                        {'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")",
                         'Result': result})
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append(
                        {'Status': craws.status['Orange'], 'Region': region['Id'] + " (" + region['ShortName'] + ")",
                         'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'UnusedSecurityGroups.json', account['account_id'])
            
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Unused Security Groups check finished')

if (__name__ == "__main__"):
    handler (None,None)