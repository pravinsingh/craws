""" This rule checks resources for any unrestriced access.
"""

__version__ = '0.2.0'
__author__ = 'Bhupender Kumar'
import boto3
import craws




def handler(event, context):
    logger = craws.get_logger(name='UnrestrictedAccess')
    logger.debug('SG with unristriced check started')

    sts = boto3.client('sts')
    
    protocol_name = { 22: 'SSH', 53: 'DNS', 21: 'FTP', 23: 'Telnet', 65535: 'All TCP' }

    for role_arn in craws.role_arns:
        results = {'Rule Name': 'Security groups with unrestriced access'}
        results['Area'] = 'EC2'
        results['Description'] = 'Check your EC2 security groups for inbound rules that allow unrestricted access (i.e. 0.0.0.0/0)'  +\
            ' to any TCP and UDP ports and restrict access to only those IP addresses that require it in order to implement' +\
            ' the principle of least privilege and reduce the possibility of a breach.'
        details = []
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName='UnrestrictedAccess')
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
        total_count = len(regions)
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        for region in regions:
            ec2_client = boto3.client('ec2', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            try:
                result = []
                response = ec2_client.describe_security_groups()
                for sec_grp_details in response['SecurityGroups']:
                    #print(s1['GroupName'], s1['IpPermissions']['IpRanges']
                    for sec_grp_perms in sec_grp_details['IpPermissions']:
                        #print(s2['IpRanges']['CidrIp'])
                        for sec_grp_rules in sec_grp_perms['IpRanges']:
                            try:
                                if sec_grp_rules['CidrIp'] == '0.0.0.0/0' and sec_grp_perms['ToPort'] in (22, 21, 23, 65535):
                                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                    #details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})
                                    red_count += 1
                                    #print(sec_grp_details['GroupId'], sec_grp_details['GroupName'], sec_grp_perms['IpProtocol'], sec_grp_rules['CidrIp'], sec_grp_perms['ToPort'])
                                    result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 'Opened Port': sec_grp_perms['ToPort'], 'Protocol Type':sec_grp_perms['IpProtocol'], 'Protocol Name': protocol_name[sec_grp_perms['ToPort']], 'CIDR': sec_grp_rules['CidrIp']})
                                else:
                                    # All good, mark it as Green
                                    green_count += 1
                            except KeyError:
                                continue
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                grey_count += 1
                
            if len(result) == 0:
                # All good, mark it as Green
                #details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
            else:
                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'UnrestrictedAccess.json', account_id)
        logger.info('Results for account %s uploaded to s3', account_id)

    logger.debug('SG with unrestriced check finished')