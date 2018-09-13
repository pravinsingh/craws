""" This rule checks resources for any unrestriced access.
"""

__version__ = '0.6.0'
__author__ = 'Bhupender Kumar'
import boto3
import craws
import datetime




def handler(event, context):
    logger = craws.get_logger(name='UnrestrictedAccess')
    logger.debug('SG with unristriced check started')

    sts = boto3.client('sts')
    
    #protocol_name = { 22: 'SSH', 53: 'DNS', 21: 'FTP', 23: 'Telnet', 65535: 'All TCP' }
    
    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/UnrestrictedAccess.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            results = {'Rule Name': 'Unrestricted Security Groups'}
            results['Area'] = 'EC2'
            results['Description'] = 'Check your EC2 security groups for inbound rules that allow unrestricted access (i.e. 0.0.0.0/0)'  +\
                ' to any TCP and UDP ports and restrict access to only those IP addresses that require it in order to implement' +\
                ' the principle of least privilege and reduce the possibility of a breach.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='UnrestrictedAccess')
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
                try:
                    result = []
                    response = ec2_client.describe_security_groups()
                    for sec_grp_details in response['SecurityGroups']:
                        #print(s1['GroupName'], s1['IpPermissions']['IpRanges']
                        for sec_grp_perms in sec_grp_details['IpPermissions']:
                            #print(s2['IpRanges']['CidrIp'])
                            for sec_grp_rules in sec_grp_perms['IpRanges']:
                                try:
                                    #port_range = range(sec_grp_perms['ToPort'] - sec_grp_perms['FromPort'])
                                    #print(port_range)
                                    if sec_grp_rules['CidrIp'] == '0.0.0.0/0':
                                        if 22 in range(sec_grp_perms['FromPort'], sec_grp_perms['ToPort']):
                                            # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                            #details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})
                                            red_count += 1
                                            orange_bool = True
                                            red_bool = True
                                            #print(sec_grp_details['GroupId'], sec_grp_details['GroupName'], sec_grp_perms['IpProtocol'], sec_grp_rules['CidrIp'], sec_grp_perms['ToPort'])
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                        elif (sec_grp_perms['FromPort'] or sec_grp_perms['ToPort']) == 22:
                                            red_count += 1
                                            orange_bool = True
                                            red_bool = True
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                        elif (sec_grp_perms['FromPort'] and sec_grp_perms['ToPort']) in (80, 443):
                                            green_count += 1
                                            # All good, mark it as Green
                                        else:
                                            result.append({'SG Id': sec_grp_details['GroupId'], 'Name': sec_grp_details['GroupName'], 'Opened Port(From)': sec_grp_perms['FromPort'], 'Opened Port(To)': sec_grp_perms['ToPort'], 'Protocol Type':sec_grp_perms['IpProtocol'], 'CIDR': sec_grp_rules['CidrIp']})
                                            orange_count += 1
                                            orange_bool = True
                                    else:
                                        green_count += 1
                                        # All good, mark it as Green
                                    
                                except KeyError:
                                    continue
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
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
            craws.upload_result_json(results, 'UnrestrictedAccess.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

        logger.debug('SG with unrestriced check finished')