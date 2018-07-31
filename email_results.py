""" Goes through all the results in the s3 bucket and sends emails to intended recipients.
"""

__version__ = '0.3.0'
__author__ = 'Pravin Singh'

import boto3
import datetime
import craws

def get_email_body(account_id, s3_client, logger):
    try:
        response = s3_client.get_object(Bucket = craws.bucket, Key = 'res/stylesheet.css')
        style = response['Body'].read()
        email_body = '<html>\n<head>\n<style>' + style + '</style>\n</head>\n<body>\n' +\
            '<table width="100%" style="border-collapse:collapse"><th width="80%">Check</th><th width="20%">Result</th>'
        
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
                green = 100
                red = orange = yellow = grey = 0
            else:
                green = int(result['GreenCount'])*100/total
                red = int(result['RedCount'])*100/total
                orange = int(result['OrangeCount'])*100/total
                yellow = int(result['YellowCount'])*100/total
                grey = int(result['GreyCount'])*100/total
            email_body += '<tr><td>' + result['Rule Name'] + '</td><td><table style="border-collapse:collapse"><tr>'
            if green > 0:
                email_body += '<td class="green-bar" width="' + str(green) + '%"></td>'
            if red > 0:
                email_body += '<td class="red-bar" width="' + str(red) + '%"></td>'
            if orange > 0:
                email_body += '<td class="orange-bar" width="' + str(orange) + '%"></td>'
            if yellow > 0:
                email_body += '<td class="yellow-bar" width="' + str(yellow) + '%"></td>'
            if grey > 0:
                email_body += '<td class="grey-bar" width="' + str(grey) + '%"></td>'
            email_body += '</tr></table></td></tr>'
        email_body += '</table><br/>'

        # Add the legends
        email_body += ('<table style="width:100%;border:hidden"><tr>'
                        + craws.status['Green'] + craws.status['Red'] + craws.status['Orange']
                        + craws.status['Yellow'] + craws.status['Grey'] + '</tr></table><br/>'
        )
        # Add the link to detailed results
        if result_url:
            email_body += 'For detailed findings, <a href="' + result_url + '">click here</a>.'
        email_body += '</body></html>'
    except Exception as e:
        logger.error(e)
    return email_body

def send_email(email_body, key, ses_client, logger):
    sender = 'noreply-notifications-cloudops@tibco.com'
    receiver = ['noreply-notifications-cloudops@tibco.com']
    destination = {
        'ToAddresses': receiver,
        'CcAddresses': [],
        'BccAddresses': []
    }
    message = {
        'Subject': {
            'Data': 'Craws results: ' + key.rstrip('/')
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
                email_body = get_email_body(key, s3_client, logger)
                send_email(email_body, key, ses_client, logger)
    except Exception as e:
        logger.error(e)
    logger.debug('Emailing results finished')

