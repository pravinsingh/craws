""" This rule checks Idle/Unused RDS instances.
"""

__version__ = '0.1.1'
__author__ = 'Anmol Saini'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='')
    logger.debug('Idle RDS instances check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        results = {'Rule Name': 'Idle RDS instances'}
        results['Area'] = 'RDS'
        results['Description'] = 'Ensure that no AWS RDS database instances is Idle/Unused to help lower '  +\
            'the cost of our monthly AWS bill .' 
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='IdleRdsInstance')
        except Exception as e:
            logger.error(e)
            continue
        credentials = response['Credentials']
        regions = craws.get_region_descriptions()
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        for region in regions:
            red_bool = green_bool = grey_bool = False
            
            ec2_client = boto3.client('ec2', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            
            rds_client = boto3.client('rds', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            
            ec2 = boto3.resource('ec2', region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
                                        
            
            cw = boto3.client('cloudwatch',region_name=region['Id'],
                                        aws_access_key_id=credentials['AccessKeyId'], 
                                        aws_secret_access_key=credentials['SecretAccessKey'], 
                                        aws_session_token=credentials['SessionToken'])
            
            try:
                
                result = []
                dbs = rds_client.describe_db_instances()
                for db in dbs['DBInstances']:
                    if db['DBInstanceStatus'] == 'available':
                        
                        response = cw.get_metric_statistics(
                        Period=3000,
                        StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                        EndTime=datetime.datetime.utcnow(),
                        MetricName='DatabaseConnections',
                        Namespace='AWS/RDS',
                        Statistics=['Average'],
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                        )
                        data = response['Datapoints'][0]['Average']
                        
                        response2 = cw.get_metric_statistics(
                        Period=3000,
                        StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                        EndTime=datetime.datetime.utcnow(),
                        MetricName='ReadIOPS',
                        Namespace='AWS/RDS',
                        Statistics=['Average'],
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                        )
                        
                        readiops=response2['Datapoints'][0]['Average']
                        
                        response3 = cw.get_metric_statistics(
                        Period=3000,
                        StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                        EndTime=datetime.datetime.utcnow(),
                        MetricName='WriteIOPS',
                        Namespace='AWS/RDS',
                        Statistics=['Average'],
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                        )
                        
                        writeiops=response3['Datapoints'][0]['Average']
                                
                        if data < 1 and readiops < 20 and writeiops < 20 :
                            result.append({'Instance ID':db['DBInstanceIdentifier'],'Master Username':db['MasterUsername'],'DB Connection':data,'ReadIOPS':readiops,'WriteIOPS':writeiops})
                            red_count += 1
                            red_bool = True
                        else:
                            green_count += 1
                            green_bool = True
                
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Grey'], 'Result': result})
                grey_count += 1
            
            if red_bool == True:
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Red'], 'Result': result})
            else:
                details.append({'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Status': craws.status['Green'], 'Result': result})

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'IdleRdsInstances.json', account['account_id'])
        logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Idle RDS instances check finished')

