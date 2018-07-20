""" Base module for project Craws that is used in all compliance-rule implementations.
"""

__version__ = '0.1.0'
__author__ = 'Pravin Singh'

import boto3
import json
import datetime
import logging
from json2html import json2html
from pkg_resources import resource_filename

""" Name of the bucket in s3 that stores all the results
"""
bucket = 'craws'

""" Role ARNs for all accounts against which the compliance rules are to be run. The roles should have read access in their
    respective accounts and should have the role crawsExecution (arn:aws:iam::926760075421:role/crawsExecution) as a trusted entity.
"""
role_arns = ['arn:aws:iam::013185853748:role/cloudops-mdm-prod-craws',
              'arn:aws:iam::926760075421:role/crawsReadOnly']

""" Traffic light symbols used to show against the results of every region. If the check did not run for a region due to an
    exception, mark that region as 'Grey' during the exception handling.
"""
status = {  'Red': '<span class="red-dot"></span> Issues - Critical ',
            'Orange': '<span class="orange-dot"></span> Issues - Medium ',
            'Yellow': '<span class="yellow-dot"></span> Issues - Minor ',
            'Green': '<span class="green-dot"></span> No Issues ',
            'Grey': '<span class="grey-dot"></span> Not Checked '}

_style = '<style>' +\
    '.red-dot { height: 15px; width: 15px; background-color: #d00; border-radius: 40%; display: inline-block; }' +\
    '.orange-dot { height: 15px; width: 15px; background-color: #f80; border-radius: 40%; display: inline-block; }' +\
    '.yellow-dot { height: 15px; width: 15px; background-color: #fd0; border-radius: 40%; display: inline-block; }' +\
    '.green-dot { height: 15px; width: 15px; background-color: #0e0;border-radius: 40%; display: inline-block; }' +\
    '.grey-dot { height: 15px; width: 15px; background-color: #ccc; border-radius: 40%; display: inline-block; }' +\
    '.red-bar { color: #fff; background-color: #f44336; height: 5px }' +\
    '.orange-bar { color: #000; background-color: #ff9800; height: 5px }' +\
    '.yellow-bar { color: #000; background-color: #ffeb3b; height: 5px }' +\
    '.green-bar { color: #fff; background-color: #4CAF50; height: 5px }' +\
    '.grey-bar { color: #000; background-color: #9e9e9e; height: 5px }' +\
    'table, h3 {font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; font-size: small; }' +\
    'table {    border: 1px solid lightgrey;    width: 100%;    border-collapse: collapse; }' +\
    'th {    border: 1px solid lightgrey;    background-color: #dddddd; text-align: left; }' +\
    'td {    border-top: 1px solid lightgrey;    border-bottom: 1px solid lightgrey;    vertical-align: middle; }' +\
    'tr:hover { background-color: #eff7fd; }' +\
    'tr:nth-child(even) { background-color: #f8f8f8 }    </style>'

_sts = boto3.client('sts')
# Create an s3 client with the role 'crawsExecution', since 'crawsExecution' is the only role with write access to our s3 bucket.
_response = _sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='UnusedElasticIps')
_s3_client = boto3.client('s3', aws_access_key_id=_response['Credentials']['AccessKeyId'], 
                            aws_secret_access_key=_response['Credentials']['SecretAccessKey'], 
                            aws_session_token=_response['Credentials']['SessionToken'])
_ec2_client = boto3.client('ec2', aws_access_key_id=_response['Credentials']['AccessKeyId'], 
                            aws_secret_access_key=_response['Credentials']['SecretAccessKey'], 
                            aws_session_token=_response['Credentials']['SessionToken'])

def _create_folder(account_id):
    try:
        today = datetime.datetime.now()
        folder_name = str(today.date()) + '/' +account_id + '/'
        _s3_client.put_object(Bucket=bucket, Key=folder_name, Body='')
        _logger.debug("Folder " + folder_name + " created for accoount " + account_id)
    except Exception as e:
        _logger.error(e)
        return None
    return folder_name

def get_html_head():
    #return '<head>' + _style + '<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"></head>'
    return '<head>' + _style + '</head>'
        
def get_result_html(result_file):
    """ Return the html formatted output of compliance check result that can be used as the email body or saved as an html page.\n
        ``result_file``: Name (key) of the json file to convert. It should contain the full path inside the bucket.
    """
    response = _s3_client.get_object(Bucket = bucket, Key = result_file)
    result = json.loads(response['Body'].read())
    details = json2html.convert(result['Details'], 
        table_attributes='style="font-size:small;"',
        escape=False)
    #details = details.replace('&lt;', '<').replace('&gt;', '>')
    text = '<h3>' + result['Rule Name'] + '</h3>' + details
    return text

def upload_result_html(html, file_name, account_id):
    try:
        _s3_client.put_object(Bucket=bucket, Key=account_id+file_name, 
                            Body=html, ContentType='text/html')
        _s3_client.put_object_acl(ACL='public-read', Bucket=bucket, Key=account_id+file_name,)
    except Exception as e:
        _logger.error(e)
    _logger.info('File %s uploaded for account %s', file_name, account_id)

def get_result_json(result_file):
    """ Get the json result of the compliance check from s3.\n
        ``result_file``: Name (key) of the json file to retrieve. It should contain the full path inside the bucket.
    """
    try:
        response = _s3_client.get_object(Bucket = bucket, Key = result_file)
        result = json.loads(response['Body'].read())
        return result
    except Exception as e:
        _logger.error(e)

def upload_result_json(result, file_name, account_id):
    """ Upload the check result json file to the s3 bucket. It creates a folder for today's date, creates a sub-folder for the account id
        and uploads the file inside that sub-folder.\n
        ``result``: Json to be uploaded.\n
        ``file_name``: File name to be used. Should be based on the rule name of the result, should NOT contain the full path in the bucket.\n
        ``account_id``: Account Id of the account against which the check was performed.
    """
    try:
        folder_name = _create_folder(account_id)
        _s3_client.put_object(Bucket=bucket, Key=folder_name+file_name, 
                                Body=json.dumps(result, indent=4), ContentType='application/json')
    except Exception as e:
        _logger.error(e)

def get_region_ids():
    """ Get a list of all the AWS region ids.
    """
    try:
        regions = [region['RegionName'] for region in _ec2_client.describe_regions()['Regions']]
        return regions
    except Exception as e:
        _logger.error(e)

def get_region_descriptions():
    """ Get a list of human-readable names for all the AWS regions.\n
    ``Response Syntax``:
    [
        {
            'Id': 'string', # Region Id
            'FullName': 'string', # Full descriptive name
            'ShortName': 'string' # City/State name of the region
        },
    ]
    """
    try:
        regions = []
        endpoint_file= resource_filename('botocore', 'data/endpoints.json')
        with open(endpoint_file, 'r') as f:
            endpoints = json.load(f)
        boto_regions = endpoints['partitions'][0]['regions']
        for ec2_region in _ec2_client.describe_regions()['Regions']:
            if ec2_region['RegionName'] not in boto_regions:
                boto_regions[ec2_region['RegionName']] = {'description': ec2_region['RegionName']}
            id = ec2_region['RegionName']
            full_name = boto_regions[ec2_region['RegionName']]['description']
            short_name = str(full_name)[full_name.find('(')+1:full_name.find(')')]
            regions.append({"Id": id, "FullName": full_name, "ShortName": short_name})
        return regions
    except Exception as e:
        _logger.error(e)

def get_logger(name='', level='WARNING'):
    """ Get the Python logger. By default, the level is set to WARNING but can be changed as needed.\n
    ``name``: Set it to the filename you are calling it from\n
    ``level``: Text logging level for the message ('DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL')
    """
    logging.basicConfig(format='%(asctime)s - %(name)s: %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    levelname = logging.getLevelName(level)
    logger.setLevel(levelname)
    return logger

_logger = get_logger(name='craws')
