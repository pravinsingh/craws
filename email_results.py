""" Goes through all the results in the s3 bucket and sends emails to intended recipients.
"""

__version__ = '0.6.1'
__author__ = 'Pravin Singh'

import boto3
import datetime
import craws

def create_email_body(account_id, s3_client, logger):
    try:
        response = s3_client.get_object(Bucket = craws.bucket, Key = 'res/stylesheet.css')
        style = response['Body'].read().decode()
        email_body = '<html>\n<head>\n<style>' + style + '</style>\n</head>\n<body>\n' +\
            '<img class="logo" src="https://s3-eu-west-1.amazonaws.com/craws/res/tibco-logo.png">\n' +\
            '<h1>CRAWS</h1>\n<h5>Compliance Reporting for AWS</h5>\n' +\
            '<table class="results-table"><th width="10%">Area</th><th width="70%">Check</th><th width="20%">Result</th>'
        result_url = ''
        response = s3_client.list_objects(Bucket = craws.bucket, Prefix = account_id)
        for result_file in response['Contents']:
            key = result_file['Key']
            if key.endswith('/'):
                continue
            if key.endswith('.html'):
                # Not a good thing to hard-code the s3 endpoint, but it seems there's no clean way to get it
                result_url = '{}/{}/{}'.format('https://s3-eu-west-1.amazonaws.com', craws.bucket, key)
                continue
            result = craws.get_result_json(key)
            total = (int(result['GreenCount']) + int(result['RedCount']) + int(result['OrangeCount']) +
                     int(result['YellowCount']) + int(result['GreyCount']))
            # If there are no results, it's considered Green
            if total == 0:
                green_percent = 100
                red_percent = orange_percent = yellow_percent = grey_percent = 0
            else:
                green_percent = int(result['GreenCount'])*100/total
                red_percent = int(result['RedCount'])*100/total
                orange_percent = int(result['OrangeCount'])*100/total
                yellow_percent = int(result['YellowCount'])*100/total
                grey_percent = int(result['GreyCount'])*100/total

            email_body += ('<tr><td>' + result['Area'] + '</td><td>' + result['Rule Name'] +
                           '</td><td><table class="bar"><tr>')
            if green_percent > 0:
                email_body += '<td class="green-bar" style="border: 1px solid white" width="' + str(green_percent) + '%"></td>'
            if red_percent > 0:
                email_body += '<td class="red-bar" style="border: 1px solid white" width="' + str(red_percent) + '%"></td>'
            if orange_percent > 0:
                email_body += '<td class="orange-bar" style="border: 1px solid white" width="' + str(orange_percent) + '%"></td>'
            if yellow_percent > 0:
                email_body += '<td class="yellow-bar" style="border: 1px solid white" width="' + str(yellow_percent) + '%"></td>'
            if grey_percent > 0:
                email_body += '<td class="grey-bar" style="border: 1px solid white" width="' + str(grey_percent) + '%"></td>'
            email_body += '</tr></table></td></tr>'
        email_body += '</table><br/>'

        # Add the legends
        email_body += ('<hr><table style="width:100%;border:hidden"><tr>'
                        + craws.status['Green'] + craws.status['Red'] + craws.status['Orange']
                        + craws.status['Yellow'] + craws.status['Grey'] + '</tr></table><hr><br>'
        )
        # Add the button for detailed results
        if result_url:
            email_body += ('<div style="text-align: center; margin: 40px"> <a href="' + result_url 
                        + '" style="border-radius:4px;padding:10px;padding-left:16px;padding-right:16px;'
                        + 'background:dodgerblue;color:white;text-decoration:none;font-size:24px;'
                        + 'text-transform:uppercase;font-weight:600;letter-spacing:1px"> View Detailed Report </a></div>')
        # Add the footer and close the html body
        email_body += ('<div style="font-size: small;color: dimgrey;background: lightgrey;padding: 5px;"><ul>'
                        + '<li> TIBCO Confidential - Internal use only. Do not share with anyone outside TIBCO.</li>'
                        + '<li> Have any feedback or suggestions on this report? Let us know at <a href="mailto:craws@tibco.com">craws@tibco.com</a>.</li>'
                        + '</ul></div></body></html>')
        email_body += '</body></html>'
    except Exception as e:
        logger.error(e)
    return email_body

def send_email(email_body, key, ses_client, logger):
    account_id = key[(key.find('/')+1):].rstrip('/')
    display_name = craws.get_account_name(account_id)
    receiver = craws.get_account_emails(account_id)
    sender = 'noreply-notifications-cloudops@tibco.com'
    destination = {
        'ToAddresses': receiver,
        'CcAddresses': [],
        'BccAddresses': []
    }
    message = {
        'Subject': {
            'Data': 'Craws Results: ' + display_name + ' (' + account_id + ')'
        },
        'Body': {
            'Html': {
                'Data': email_body
            }
        }
    }
    response = ses_client.send_email(Source = sender, Destination = destination, Message = message)
    if response:
        logger.info('Email sent for account %s', key[key.find('/')+1:].rstrip('/'))

def handler(event, context):
    logger = craws.get_logger(name='EmailResults', level='DEBUG')
    logger.debug('Emailing results started')
    # Creates an s3 client with the role 'crawsExecution', since 'crawsExecution' is the only role with write access to 
    # our s3 bucket and permission to send emails.
    sts = boto3.client('sts')
    response = sts.assume_role(RoleArn='arn:aws:iam::926760075421:role/crawsExecution', RoleSessionName='EmailResults')
    s3_client = boto3.client('s3', aws_access_key_id=response['Credentials']['AccessKeyId'], 
                                aws_secret_access_key=response['Credentials']['SecretAccessKey'], 
                                aws_session_token=response['Credentials']['SessionToken'])
    ses_client = boto3.client('ses', aws_access_key_id=response['Credentials']['AccessKeyId'], 
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
                email_body = create_email_body(key, s3_client, logger)
                send_email(email_body, key, ses_client, logger)
    except Exception as e:
        logger.error(e)
    logger.debug('Emailing results finished')

