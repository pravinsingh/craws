""" This rule checks default EC2 Security Groups in use.
"""

__version__ = '0.2.0'
__author__ = 'Bhupender Kumar'
import boto3
import craws




def handler(event, context):
    logger = craws.get_logger(name='')
    logger.debug('default SG in use check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        results = {'Rule Name': 'Default Security Groups In Use'}
        results['Area'] = 'EC2'
        results['Description'] = 'Ensure that the provisioned EC2 instances are not associated with default security groups created alongside with VPCs in order to '  +\
            'enforce using custom and unique security groups that exercise the principle of least privilege.' 
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='defaultSGinuse')
        except Exception as e:
            logger.error(e)
            continue
        credentials = response['Credentials']
        regions = craws.get_region_descriptions()
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        for region in regions:
            ec2_client = boto3.client('ec2', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            try:
                result = []
                default_sec_grps = []
                response = ec2_client.describe_security_groups()
                for sec_grp_details in response['SecurityGroups']:
                    if sec_grp_details['Description'] == 'default VPC security group' and sec_grp_details['GroupName'] == 'default' and sec_grp_details['GroupId'] not in default_sec_grps:
                        default_sec_grps.append(sec_grp_details['GroupId'])
                        #print(s1['GroupId'])
                        
                network_interfaces = ec2_client.describe_network_interfaces()
                for net_sec_grps in network_interfaces['NetworkInterfaces']:
                    for sec_grp in net_sec_grps['Groups']:
                        try:
                            if sec_grp['GroupId'] in default_sec_grps:
                                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                orange_count += 1
                                result.append({'SG Id': sec_grp['GroupId'], 'InstanceId': net_sec_grps['Attachment']['InstanceId']})
                               #print("Attached to default SG" ,grp['GroupId'], ni['Attachment']['InstanceId']
                            else:
                                #print("Not attached to default SG" ,grp['GroupId'], ni['Attachment']['InstanceId'])
                                # All good, mark it as Green
                                green_count += 1
                        except:
                            continue
                        
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                grey_count += 1
            
            if len(result) == 0:
                # All good, mark it as Green
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
            else:
                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Orange'], 'Result': result})


        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'defaultSGinuse.json', account['account_id'])
        logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('default SG in use check finished')