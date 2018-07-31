""" Goes through all the results in the s3 bucket, generates a consolidated report and uploads it back to s3.
"""

__version__ = '0.3.0'
__author__ = 'Pravin Singh'

import boto3
import datetime
import json
import craws
from json2html import json2html

def get_result(key, s3_client):
    """ Get the html section for a rule's result json file.\n
        ``key``: Name (key) of the json file to convert. It should contain the full path inside the bucket.
    """
    response = s3_client.get_object(Bucket = craws.bucket, Key = key)
    result = json.loads(response['Body'].read())
    details = json2html.convert(result['Details'], escape=False)
    area = str(result['Area']).upper()
    total = (int(result['GreenCount']) + int(result['RedCount']) + int(result['OrangeCount']) +
            int(result['YellowCount']) + int(result['GreyCount']))
    # If there are no results, it's considered Green
    if total == 0:
        green = 100
        red = orange = yellow = grey = 0
    else:
        green = int(result['GreenCount'])*100/total
        red = int(result['RedCount'])*100/total
        orange = int(result['OrangeCount'])*100/total
        yellow = int(result['YellowCount'])*100/total
        grey = int(result['GreyCount'])*100/total

    heading = '<img src="../../res/' + area + '.png"><div class="area">' + area + '</div>'
    content = '<div class="collapsible">' + result['Rule Name'] +\
        '<table style="float:right; width: 100px; margin-right: 15px; margin-top: 6px;">' +\
        '<tr><td class="green-bar" width="' + str(green) + '%"></td>' +\
        '<td class="red-bar" width="' + str(red) + '%"></td>' +\
        '<td class="orange-bar" width="' + str(orange) + '%"></td>' +\
        '<td class="yellow-bar" width="' + str(yellow) + '%"></td>' +\
        '<td class="grey-bar" width="' + str(grey) + '%"></td></tr></table></div><div class="content">' +\
        '<div class="description">' + result['Description'] + '</div>' + details + '</div>'
    return heading, content

def generate_report(key, s3_client, logger):
    """ Generate a report for an account, combining all the results
    """
    account_id = key[key.find('/')+1:key.rfind('/')]
    date = str(datetime.datetime.now().date())
    head = '\n<head><title>CRAWS Results - ' + account_id + '</title>\n</head>\n'
    report = '<html>' + head + '<body>\n<h1>CRAWS Results</h1>\n<h4>(Compliance Reporting for AWS)</h4>\n' +\
        '<table class="header"><tr class="header"><td class="header">Date: <b>' + date +\
        '</b></td><td class="header">Account: <b>' + account_id + '</b></td><td style="border: none; width: 250px">' +\
        '<button id="toggleBtn" onclick="toggleAll()" height="30px" >Expand All</button></td></tr></table>\n'
    try:
        response = s3_client.list_objects(Bucket = craws.bucket, Prefix = key)
        for result_file in response['Contents']:
            key = result_file['Key']
            if key.endswith('/') or key.endswith('.html'):
                continue
            heading, content = get_result(key, s3_client)

            # If this result's area is already present in the report, insert the result there, otherwise create a new section
            # at the bottom
            if heading in report:
                index = report.find(heading) + len(heading)
                report = report[:index] + content + report[index:]
            else:
                report = report + heading + content

        report += '\n<script src="../../res/script.js"></script>\n' +\
            '<link rel="stylesheet" type="text/css" href="../../res/stylesheet.css">\n</body>\n</html>'
    except Exception as e:
        logger.error(e)
    return report

def handler(event, context):
    """ Loop through all accounts and generate a report for every account
    """
    logger = craws.get_logger(name='GenerateReports', level='DEBUG')
    logger.debug('Generating Reports started')
    # Creates an s3 client with the role 'crawsExecution', since 'crawsExecution' is the only role with write access to 
    # our s3 bucket and permission to send emails.
    sts = boto3.client('sts')
    response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='GenerateReports')
    s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                aws_session_token=response['Credentials']['SessionToken'])

    try:
        today = str(datetime.datetime.now().date())
        response = s3_client.list_objects(Bucket = craws.bucket, Prefix = today)
        for account in response['Contents']:
            key = account['Key']
            # Ignore the Results.html file
            if key.endswith('.html'):
                continue
            # Keys ending with '/' are account folders
            if str(key).endswith('/'):
                report = generate_report(key, s3_client, logger)
                craws.upload_result_html(report, 'Result.html', key)
    except Exception as e:
        logger.error(e)
    logger.debug('Generating Reports finished')

