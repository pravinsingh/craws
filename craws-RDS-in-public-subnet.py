""" This rule checks and reports RDS in public subnets.
"""

__version__ = '0.3.0'
__author__ = 'Bhupender Kumar'
import boto3
import craws




def handler(event, context):
    logger = craws.get_logger(name='')
    logger.debug('RDS in public subnet check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        results = {'Rule Name': 'RDS in public subnet'}
        results['Area'] = 'RDS'
        results['Description'] = 'Ensure that no AWS RDS database instances are provisioned inside VPC public subnets in order to protect them from direct exposure to the Internet. Since database instances are not Internet-facing '  +\
            'and their management (running software updates, implementing security patches, etc) is done by Amazon, these instances should run only in private subnets.' 
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
            try:
                
                result = []
                
                public_subnets = []
                
                #response = ec2_client.describe_internet_gateways()
                response = ec2_client.describe_route_tables()
                #print(region['RegionName'])
                for rtbl_details in response['RouteTables']:
                #print(v1)
                    for rtbl_comp in rtbl_details['Associations']:
                    #print(v1['Associations']['SubnetId'], v2['GatewayId'])
                        for rtbl_routes in rtbl_details['Routes']:
                            try:
                                if rtbl_routes['GatewayId'].find("igw") == -1:
                                    continue
                                else:
                                    if rtbl_comp['SubnetId'] not in public_subnets:
                                        public_subnets.append(rtbl_comp['SubnetId'])
                                        #print(v2['SubnetId'], v3['GatewayId'])
                            except KeyError:
                                continue
                
                resp = rds_client.describe_db_instances()
                for db_details in resp['DBInstances']:
                #print(d1['DBSubnetGroup']['Subnets']):
                    for db_subnet in db_details['DBSubnetGroup']['Subnets']:
                    #print(d1['DBInstanceIdentifier'], d2['SubnetIdentifier'])
                        if db_subnet['SubnetIdentifier'] in public_subnets and db_details['PubliclyAccessible'] == False:
                            # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                            orange_count += 1
                            orange_bool = True
                            result.append({'Subnet Group': db_subnet['SubnetIdentifier'], 'RDS Instance': db_details['DBInstanceIdentifier'], 'Publicly Accessible': db_details['PubliclyAccessible']})
                            #print("Problem", d1['DBInstanceIdentifier'], d2['SubnetIdentifier'], d1['PubliclyAccessible'])
                        elif db_subnet['SubnetIdentifier'] in public_subnets and db_details['PubliclyAccessible'] == True:
                            # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                            red_count += 1
                            red_bool = True
                            result.append({'Subnet Group': db_subnet['SubnetIdentifier'], 'RDS Instance': db_details['DBInstanceIdentifier'], 'Publicly Accessible': db_details['PubliclyAccessible']})
                        else:
                            #print("Safe", d1['DBInstanceIdentifier'], d2['SubnetIdentifier'], d1['PubliclyAccessible'])
                            # All good, mark it as Green
                            green_count += 1
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
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
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})
                


        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'RDSinPublicSubnet.json', account['account_id'])
        logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('RDS in public subnet check finished')