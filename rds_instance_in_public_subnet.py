""" This rule checks and reports RDS in public subnets.
"""

__version__ = '0.7.1'
__author__ = 'Bhupender Kumar'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='RDSinPublicSubnet', level='DEBUG')
    logger.debug('RDS in Public Subnet check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Chack if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/RDSinPublicSubnet.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'RDS in Public Subnet'}
            results['Area'] = 'RDS'
            results['Description'] = 'Ensure that no AWS RDS database instances are provisioned inside VPC public subnets in order ' +\
                                    'to protect them from direct exposure to the Internet. Since database instances are not ' +\
                                    'Internet-facing and their management (running software updates, implementing security patches, ' +\
                                    'etc) is done by Amazon, these instances should run only in private subnets.'
            details = []
            try:
                response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='RDSinPublicSubnet')
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
                rds_client = boto3.client('rds', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                    aws_access_key_id=credentials['AccessKeyId'], 
                                    aws_secret_access_key=credentials['SecretAccessKey'], 
                                    aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    public_subnets = []
                    response = ec2_client.describe_route_tables()
                    for rtbl_details in response['RouteTables']:
                        for rtbl_comp in rtbl_details['Associations']:
                            for rtbl_routes in rtbl_details['Routes']:
                                try:
                                    if rtbl_routes['GatewayId'].find("igw") == -1:
                                        continue
                                    else:
                                        if rtbl_comp['SubnetId'] not in public_subnets:
                                            public_subnets.append(rtbl_comp['SubnetId'])
                                except KeyError:
                                    continue
                
                    resp = rds_client.describe_db_instances()
                    db_identifier = []
                    for db_details in resp['DBInstances']:
                        for db_subnet in db_details['DBSubnetGroup']['Subnets']:
                            if db_subnet['SubnetIdentifier'] in public_subnets:
                                if db_details['PubliclyAccessible'] == False:
                                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                    orange_count += 1
                                    orange_bool = True
                                    instance_id = craws.get_cloudtrail_data(lookup_value=db_details['DBInstanceIdentifier'], 
                                            cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                    result.append({'Subnet Group': db_subnet['SubnetIdentifier'], 'RDS Instance': instance_id, 
                                            'Publicly Accessible': db_details['PubliclyAccessible']})
                                    db_identifier.append(db_details['DBInstanceIdentifier'])
                                else:
                                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                                    red_count += 1
                                    orange_bool = True
                                    red_bool = True
                                    instance_id = craws.get_cloudtrail_data(lookup_value=db_details['DBInstanceIdentifier'], 
                                            cloudtrail_client=cloudtrail_client, region_id=region['Id'])
                                    result.append({'Subnet Group': db_subnet['SubnetIdentifier'], 'RDS Instance': instance_id, 
                                            'Publicly Accessible': db_details['PubliclyAccessible']})
                                    db_identifier.append(db_details['DBInstanceIdentifier'])
                            else:
                                if db_details['DBInstanceIdentifier'] not in db_identifier:
                                    # All good, mark it as Green
                                    green_count += 1
                except Exception as e:
                    logger.error(e)
                    # Exception occured, mark it as Grey (not checked)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
            
                if orange_bool == True:
                    if red_bool == True:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Red'],'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    else:
                        # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                        details.append({'Status': craws.status['Orange'],'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                else:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})

            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'RDSinPublicSubnet.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('RDS in Public Subnet check finished')