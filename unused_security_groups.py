""" This rule checks for any unused security groups in AWS account.
"""

__version__ = '0.3.0'
__author__ = 'Bhupender Kumar'
import boto3
import craws




def handler(event, context):
    logger = craws.get_logger(name='UnusedSecurityGroups')
    logger.debug('Unused security groups check started')

    sts = boto3.client('sts')
    

    for account in craws.accounts:
        results = {'Rule Name': 'Unused Security Groups in AWS Account'}
        results['Area'] = 'EC2'
        results['Description'] = 'This rule checks the unused and dangling security groups in the AWS account.Security groups that'  +\
            ' are not attached to any resource should be deleted to minimize the surface of attack'
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='unused_SG')
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
                sgrps = ec2_client.describe_security_groups()
                all_sgrps = set([sg['GroupId'] for sg in sgrps['SecurityGroups']])
                # print(all_sgs)
                used_sgrps = set()
                net_interface = ec2_client.describe_network_interfaces()
                for interface in net_interface['NetworkInterfaces']:
                    for grp in interface['Groups']:
                        used_sgrps.add(grp['GroupId'])
                green_count += len(list(used_sgrps)
                        # print all_ni_sgs
                unused_sgs = all_sgrps - used_sgrps
                #print(list(unused_sgs))
                for unused_sec_grp in list(unused_sgs):
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    #details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})
                    orange_count += 1
                    result.append({'Security Group Id': unused_sec_grp})
                    
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
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Orange'], 'Result': result})

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'UnusedSecurityGroups.json', account['account_id'])
        logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Unused security groups check finished')