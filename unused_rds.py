""" This rule checks Idle/Unused RDS instances.
"""

__version__ = '0.3.0'
__author__ = 'Anmol Saini'
import boto3
import craws
import datetime

def handler(event, context):
    logger = craws.get_logger(name='')
    logger.debug('Idle RDS instances check started')

    sts = boto3.client('sts')
    
    for account in craws.accounts:
        try:
            # Check if this rule has already been executed today for this account
            response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
            s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                    aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                    aws_session_token=response['Credentials']['SessionToken'])
            today = str(datetime.datetime.now().date())
            response = s3_client.head_object(Bucket = craws.bucket, Key = today+'/'+account['account_id']+'/IdleRdsInstances.json')
            logger.info('Account ' + account['account_id'] + ' already checked. Skipping.')
        except Exception:
            # This rule has not been executed today for this account, go ahead and execute
            results = {'Rule Name': 'Idle RDS Instances'}
            results['Area'] = 'RDS'
            results['Description'] = 'Ensure that no AWS RDS database instances is Idle/Unused to help lower the cost of our monthly AWS bill. ' + \
                                    'An RDS instance is considered &#39;idle&#39; when it meets the following criteria (to declare the instance &#39;idle&#39; both conditions must be true): ' + \
    				                '<br>- The average number of database connections has been less than 1 for the last 7 days. ' + \
    				                '<br>- The total number of database ReadIOPS and WriteIOPS recorded per day for the last 7 days has been less than 20 on average. '
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
                yellow_bool = False
                
                rds_client = boto3.client('rds', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                cloudwatch_client = boto3.client('cloudwatch',region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                cloudtrail_client = boto3.client('cloudtrail', region_name=region['Id'],
                                            aws_access_key_id=credentials['AccessKeyId'], 
                                            aws_secret_access_key=credentials['SecretAccessKey'], 
                                            aws_session_token=credentials['SessionToken'])
                try:
                    result = []
                    dbs = rds_client.describe_db_instances()
                    for db in dbs['DBInstances']:
                        if db['DBInstanceStatus'] == 'available':
                            
                            response = cloudwatch_client.get_metric_statistics(
                                Period=3000,
                                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                                EndTime=datetime.datetime.utcnow(),
                                MetricName='DatabaseConnections',
                                Namespace='AWS/RDS',
                                Statistics=['Average'],
                                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                            )
                            data = response['Datapoints'][0]['Average']
                            
                            response2 = cloudwatch_client.get_metric_statistics(
                                Period=3000,
                                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                                EndTime=datetime.datetime.utcnow(),
                                MetricName='ReadIOPS',
                                Namespace='AWS/RDS',
                                Statistics=['Average'],
                                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                            )
                            readiops=response2['Datapoints'][0]['Average']
                            
                            response3 = cloudwatch_client.get_metric_statistics(
                                Period=3000,
                                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=604800),
                                EndTime=datetime.datetime.utcnow(),
                                MetricName='WriteIOPS',
                                Namespace='AWS/RDS',
                                Statistics=['Average'],
                                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}]
                            )
                            writeiops=response3['Datapoints'][0]['Average']
                                    
                            if (data < 1) and (readiops < 20) and (writeiops < 20):
                                db['DBInstanceIdentifier'] = craws.get_cloudtrail_data(lookup_value=db['DBInstanceIdentifier'], cloudtrail_client=cloudtrail_client)
                                result.append({'Instance ID':db['DBInstanceIdentifier'],'Master Username':db['MasterUsername'],
                                        'Average DB Connections':"%.2f" % data,'Average ReadIOPS':"%.2f" % readiops,'Average WriteIOPS':"%.2f" % writeiops})
                                yellow_count += 1
                                yellow_bool = True
                            else:
                                green_count += 1
                    
                    if yellow_bool == True:
                        details.append({'Status': craws.status['Yellow'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    else:
                        details.append({'Status': craws.status['Green'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                except Exception as e:
                    # Exception occured, mark it as Grey (not checked)
                    logger.error(e)
                    details.append({'Status': craws.status['Grey'], 'Region': region['Id'] + " (" + region['ShortName'] + ")", 'Result': result})
                    grey_count += 1
    
            results['Details'] = details
            results['GreenCount'] = green_count
            results['RedCount'] = red_count
            results['OrangeCount'] = orange_count
            results['YellowCount'] = yellow_count
            results['GreyCount'] = grey_count
            craws.upload_result_json(results, 'IdleRdsInstances.json', account['account_id'])
            logger.info('Results for account %s uploaded to s3', account['account_id'])

    logger.debug('Idle RDS instances check finished')

