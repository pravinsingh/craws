""" Goes through all the results in the s3 bucket, generates a consolidated report and uploads it back to s3.
"""

__version__ = '0.9.1'
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
    details = json2html.convert(json=result['Details'], table_attributes='class="results-table"', escape=False)
    area = str(result['Area'])
    total_count = (int(result['GreenCount']) + int(result['RedCount']) + int(result['OrangeCount']) +
            int(result['YellowCount']) + int(result['GreyCount']))
    # If there are no results, it's considered Green
    if total_count == 0:
        green_percent = 100
        red_percent = orange_percent = yellow_percent = grey_percent = 0
    else:
        green_percent = int(result['GreenCount'])*100/total_count
        red_percent = int(result['RedCount'])*100/total_count
        orange_percent = int(result['OrangeCount'])*100/total_count
        yellow_percent = int(result['YellowCount'])*100/total_count
        grey_percent = int(result['GreyCount'])*100/total_count

    heading = '\n<img class="area-icon" src="../../res/' + area + '.png"><div class="area">' + area + '</div>\n'
    content = ('\n<div class="collapsible">' + result['Rule Name']
        + '\n\t<table class="bar">\n\t<tr>'
        + ('\n\t\t<td class="green-bar" width="' + str(green_percent) + '%"></td>' if green_percent > 0 else '')
        + ('\n\t\t<td class="red-bar" width="' + str(red_percent) + '%"></td>' if red_percent > 0 else '')
        + ('\n\t\t<td class="orange-bar" width="' + str(orange_percent) + '%"></td>' if orange_percent > 0 else '')
        + ('\n\t\t<td class="yellow-bar" width="' + str(yellow_percent) + '%"></td>' if yellow_percent > 0 else '')
        + ('\n\t\t<td class="grey-bar" width="' + str(grey_percent) + '%"></td>' if grey_percent > 0 else '')
        + '\n\t</tr>\n\t</table>\n</div>\n\n<div class="content">\n'
        + '\n\t<div class="description">' + result['Description'] + '</div>'
        + '\n\t<table class="summary-table">\n\t\t<tr><th >Total items:</th ><th >' + str(total_count) + '</th ></tr>'
        + '\n\t\t<tr><td><span class="green-dot"></span> Items with No issues:</td><td>' + str(result['GreenCount']) + '</td></tr>'
        + '\n\t\t<tr><td><span class="red-dot"></span> Items with Critical issues:</td><td>' + str(result['RedCount']) + '</td></tr>'
        + '\n\t\t<tr><td><span class="orange-dot"></span> Items with Medium issues:</td><td>' + str(result['OrangeCount']) + '</td></tr>'
        + '\n\t\t<tr><td><span class="yellow-dot"></span> Items with Minor issues:</td><td>' + str(result['YellowCount']) + '</td></tr>'
        + '\n\t\t<tr><td><span class="grey-dot"></span> Items Not checked:</td><td>' + str(result['GreyCount']) + '</td></tr></table>\n\t'
        + details + '\n\t</div>\n')
    return heading, content

def generate_report(key, s3_client, logger):
    """ Generate a report for an account, combining all the results
    """
    account_id = key[key.find('/')+1:key.rfind('/')]
    display_name = craws.get_account_name(account_id)
    date = str(datetime.datetime.now().date())
    head = ('\n<head><title>CRAWS - ' + display_name + '</title>\n<link rel="stylesheet" type="text/css" href="../../res/stylesheet.css">\n'
        + '<link rel="stylesheet" href="../../res/jquery-ui/jquery-ui.css">\n<script src="https://code.jquery.com/jquery-1.12.4.js"></script>\n'
        + '<script src="../../res/jquery-ui/jquery-ui.js"></script>\n<script>\n\t$(function() {\n\t\t$("#datepicker").datepicker({\n\t\t\t'
        + 'showOn: "both",\n\t\t\tbuttonImage:"../../res/jquery-ui/images/calendar.png",\n\t\t\tmaxDate: 0\n\t\t});'
        + '\n\t\t$( "#datepicker" ).datepicker("option", "dateFormat", "yy-mm-dd");'
        + '\n\t\t$( "#datepicker" ).datepicker("option", "defaultDate", 0);'
        + '\n\t\tdocument.getElementById("datepicker").value = "'+ date + '";'
        + '\n\t\t$("#toggleBtn").button();'
        + '\n\t\t$("#theme").selectmenu({'
        + '\n\t\t\tchange: function(event, data) {'
        + '\n\t\t\t\tswitch(data.item.value) {'
        + '\n\t\t\t\t\tcase "Dodger Blue":'
        + '\n\t\t\t\t\t\t$(".collapsible").css("background", "linear-gradient(to left, aliceblue, transparent 400px), '
        + 'linear-gradient(aliceblue, dodgerblue, dodgerblue)");'
        + '\n\t\t\t\t\t\t$(".summary-table").css("background", "aliceblue");'
        + '\n\t\t\t\t\t\tbreak;'
        + '\n\t\t\t\t\tcase "Sandy Brown":'
        + '\n\t\t\t\t\t\t$(".collapsible").css("background", "linear-gradient(to left, papayawhip, transparent 400px), '
        + 'linear-gradient(papayawhip, sandybrown, sandybrown)");'
        + '\n\t\t\t\t\t\t$(".summary-table").css("background", "papayawhip");'
        + '\n\t\t\t\t\t\tbreak;'
        + '\n\t\t\t\t\tcase "Dim Grey":'
        + '\n\t\t\t\t\t\t$(".collapsible").css("background", "linear-gradient(to left, lightgrey, transparent 400px), '
        + 'linear-gradient(lightgrey, dimgrey, dimgrey)");'
        + '\n\t\t\t\t\t\t$(".summary-table").css("background", "lightgrey");'
        + '\n\t\t\t\t}\n\t\t\t}\n\t\t});'
        + '\n\t\t$(document).tooltip( {'
        + '\n\t\t\titems: "[title]",'
        + '\n\t\t\tcontent: function() {'
        + '\n\t\t\t\treturn $(this).next().html();\n\t\t\t},'
        + '\n\t\t\tclasses: {'
        + '\n\t\t\t\t"ui-tooltip-content": "results-table tooltip"'
        + '\n\t\t\t}\n\t\t});'
        + '\n\t} );\n</script>\n</head>\n')
    report = ('<html>' + head + '<body>\n<img class="logo" src="../../res/tibco-logo.png"><h1>CRAWS</h1>\n'
        + '<h5>Compliance Reporting for AWS</h5>\n<table class="header"><tr class="header">'
        + '\n\t<td class="header">Account: <b id="account">' + display_name + ' (' + account_id + ')' + '</b></td>'
        + '\n\t<td class="header" style="text-align: right"><button id="toggleBtn" onclick="toggleAll()">Expand All</button></td></tr><tr>'
        + '\n\t<td class="header">Date: <input class="date ui-button" id="datepicker" onfocus="this.oldValue = this.value;" onchange="fetchReport()"></td>'
        + '\n\t<td class="header" style="text-align: right"><select id="theme"><option disabled selected>Change Theme</option>'
        + '<option>Dodger Blue</option><option>Sandy Brown</option><option>Dim Grey</option></select></td>\n</tr></table>\n')
    try:
        response = s3_client.list_objects(Bucket = craws.bucket, Prefix = key)
        for result_file in response['Contents']:
            key = result_file['Key']
            if key.endswith('/') or key.endswith('.html'):
                continue
            heading, content = get_result(key, s3_client)

            # If this result's area is already present in the report, insert the result there, 
            # otherwise create a new section at the bottom
            if heading in report:
                index = report.find(heading) + len(heading)
                report = report[:index] + content + report[index:]
            else:
                report = report + heading + content

        report += '\n<script src="../../res/script.js"></script>\n</body>\n</html>' 
        report = make_tables_sortable(report)
    except Exception as e:
        logger.error(e)
    return report

def make_tables_sortable(report):
    table_index = 0
    while (report.find('<table class="results-table">')) != -1:
        col_index = 0
        start = report.find('<table class="results-table">')
        end = report.find('<table class="results-table">', start+1)
        report = report.replace('<table class="results-table">', '\n<table class="results-table" id="table'+str(table_index)+'">', 1)
        while (report[start:end].find('<th>')) != -1:
            report = report.replace('<th>', '<th onclick="sortTable('+str(col_index)+', \'table'+str(table_index)+'\')">', 1)
            col_index += 1
        table_index += 1
    report = report.replace('</th>', '<img class="sort" src="../../res/sort.png"></th>')
    return report
    
def handler(event, context):
    """ Loop through all accounts and generate a report for every account
    """
    logger = craws.get_logger(name='GenerateReports', level='DEBUG')
    logger.debug('Generating Reports started')
    # Creates an s3 client with the role 'crawsExecution', since 'crawsExecution' is the only role with write access to 
    # our s3 bucket.
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
                logger.debug('Report generated for account ' + key)
    except Exception as e:
        logger.error(e)
    logger.debug('Generating Reports finished')

handler(None,None)