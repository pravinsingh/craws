""" This rule checks for any unrestriced security groups.
"""

__version__ = '0.7.1'
__author__ = 'Bhupender Kumar'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='UnrestrictedSecurityGroups')
    logger.debug('Unrestricted Security Groups check started')

    sts = boto3.client('sts')

    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/UnrestrictedSecurityGroups.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            results = {'Rule Name': 'Unrestricted Security Groups'}
            results['Area'] = 'EC2'
            results['Description'] = 'Check your EC2 security groups for inbound rules that allow unrestricted access (i.e. 0.0.0.0/0) '  +\
                                    'to any TCP and UDP ports and restrict access to only those IP addresses that require it in order ' +\
                                    'to implement the principle of least privilege and reduce the possibility of a breach.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='UnrestrictedSecurityGroups')
            except Exception as e:
                logger.error(e)
                continue
            credentials = response['Credentials']
            regions = craws.get_region_descriptions()
            green_count = red_count = orange_count = yellow_count = grey_count = 0

            for region in regions:
                red_bool = orange_bool = False
            
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
                    response = ec2_client.describe_security_groups()
                    for sec_grp_details in response['SecurityGroups']:
                        for sec_grp_perms in sec_grp_details['IpPermissions']:
                            for sec_grp_rules in sec_grp_perms['IpRanges']:
                                try:
                                    if sec_grp_rules['CidrIp'] == '0.0.0.0/0':
                                        if 22 in range(sec_grp_perms['FromPort'], sec_grp_perms['ToPort']):
                                            # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                            red_count += 1
                                            orange_bool = True
                                            red_bool = True
                                            sec_grp_details['GroupId'] = craws.get_cloudtrail_data(lookup_value=sec_grp_details['GroupId'], 
                                                    cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 
                                                    'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 
                                                    'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                        elif (sec_grp_perms['FromPort'] or sec_grp_perms['ToPort']) == 22:
                                            red_count += 1
                                            orange_bool = True
                                            red_bool = True
                                            sec_grp_details['GroupId'] = craws.get_cloudtrail_data(lookup_value=sec_grp_details['GroupId'], 
                                                    cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 
                                                    'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 
                                                    'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                        elif (sec_grp_perms['FromPort'] and sec_grp_perms['ToPort']) in (80, 443):
                                            # All good, mark it as Green
                                            green_count += 1
                                        else:
                                            sec_grp_details['GroupId'] = craws.get_cloudtrail_data(lookup_value=sec_grp_details['GroupId'], 
                                                    cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 
                                                    'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 
                                                    'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                            orange_count += 1
                                            orange_bool = True
                                    else:
                                        # All good, mark it as Green
                                        green_count += 1
                                except KeyError:
                                    continue
                except Exception as e:
                    # Exception occured, mark it as Grey (not checked)
                    logger.error(e)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
                
                if orange_bool == True:
                    if red_bool == True:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Red'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    else:
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
            craws.upload_result_json(results, 'UnrestrictedSecurityGroups.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Unrestricted Security Groups check finished')

