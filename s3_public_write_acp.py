""" This rule checks for s3 buckets with 'WRITE_ACP' access open to everyone.
"""

__version__ = '0.1.0'
__author__ = 'Pravin Singh'

import boto3
import craws


def handler(event, context):
    logger = craws.get_logger(name='S3PublicWriteAcp', level='DEBUG')
    logger.debug('S3 Public Write Acp check started')
    sts = boto3.client('sts')

    for account in craws.accounts:
        results = {'Rule Name': 'S3 Bucket Public WRITE_ACP Access'}
        results['Area'] = 'S3'
        results['Description'] = 'Granting public &#39;WRITE_ACP&#39; access to your S3 buckets can allow anonymous users to ' +\
            'edit their ACL permissions and eventually be able to view, upload, modify and delete S3 objects within the bucket ' +\
            'without restrictions, which can lead to data loss or economic denial-of-service attacks (i.e. uploading a large ' +\
            'number of files to drive up the costs of the S3 service within your AWS account).'
        details = []
        try:
            response = sts.assume_role(RoleArn=account['role_arn'], RoleSessionName='S3PublicWriteAcp')
        except Exception as e:
            logger.error(e)
            continue
        credentials = response['Credentials']
        green_count = red_count = orange_count = yellow_count = grey_count = 0

        s3_client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'], 
                                       aws_secret_access_key=credentials['SecretAccessKey'], 
                                       aws_session_token=credentials['SessionToken'])
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            try:
                found = False
                response = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                for grant in response['Grants']:
                    if ('URI' in grant['Grantee']
                            and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers'
                            and (grant['Permission'] == 'WRITE_ACP' or grant['Permission'] == 'FULL_CONTROL')):
                        found = True
                        break
                if found == True:
                    # Some issues found, mark it as Red/Orange/Yellow depending on this check's risk level
                    details.append({'Status': craws.status['Red'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                    red_count += 1
                else:
                    # All good, mark it as Green
                    details.append({'Status': craws.status['Green'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                    green_count += 1
            except Exception as e:
                logger.error(e)
                # Exception occured, mark it as Grey (not checked)
                details.append({'Status': craws.status['Grey'], 'Bucket':bucket['Name'], 
                                    'Owner':response['Owner']['DisplayName'] if 'DisplayName' in response['Owner'] else ''})
                grey_count += 1

        results['Details'] = details
        results['GreenCount'] = green_count
        results['RedCount'] = red_count
        results['OrangeCount'] = orange_count
        results['YellowCount'] = yellow_count
        results['GreyCount'] = grey_count
        craws.upload_result_json(results, 'S3PublicWriteAcp.json', account['account_id'])
        logger.info('Results for accout %s uploaded to s3', account['account_id'])

    logger.debug('S3 Public Write Acp check finished')


        
handler(None,None)
