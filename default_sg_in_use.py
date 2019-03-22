""" This rule checks default EC2 Security Groups in use.
"""

__version__ = '0.6.1'
__author__ = 'Bhupender Kumar'
import boto3
import craws
import datetime


def handler(event, context):
    logger = craws.get_logger(name='DefaultSgInUse')
    logger.debug('Default SG in Use check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/DefaultSgInUse.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Default Security Groups in Use'}
            results['Area'] = 'EC2'
            results['Description'] = 'Ensure that the provisioned EC2 instances are not associated with default security groups created alongside with VPCs in order to '  +\
                'enforce using custom and unique security groups that exercise the principle of least privilege.' 
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='DefaultSgInUse')
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
            
                elb_client = boto3.client('elb', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
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
                            green_count += 1
                        
                    network_interfaces = ec2_client.describe_network_interfaces()
                    for net_sec_grps in network_interfaces['NetworkInterfaces']:
                        for sec_grp in net_sec_grps['Groups']:
                            try:
                                if sec_grp['GroupId'] in default_sec_grps and net_sec_grps['Attachment']['InstanceId']:
                                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                    orange_count += 1
                                    green_count -= 1
                                    sec_grp['GroupId'] = craws.get_cloudtrail_data(sec_grp['GroupId'], cloudtrail_client, region['Id'])
                                    result.append({'SG Id': sec_grp['GroupId'], 'InstanceId/ELB Name': net_sec_grps['Attachment']['InstanceId']})
                                else:
                                    # All good, mark it as Green
                                    pass
                            except:
                                continue
                        
                    elb_desciption = elb_client.describe_load_balancers()        
                    for elb_details in elb_desciption['LoadBalancerDescriptions']:
                        for elb_sg in elb_details['SecurityGroups']:
                            if elb_sg in default_sec_grps:
                                # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                orange_count += 1
                                green_count -= 1
                                elb_sg = craws.get_cloudtrail_data(elb_sg, cloudtrail_client, region['Id'])
                                result.append({'SG Id': elb_sg, 'InstanceId/ELB Name': elb_details['LoadBalancerName']})
                        
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
            
                if len(result) == 0:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                else:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Status': craws.status['Orange'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})


            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'DefaultSgInUse.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Default SG in Use check finished')
