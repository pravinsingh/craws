# CRAWS
CRAWS (Compliance Reporting for AWS) is a serverless tool that monitors multiple AWS accounts for various security vulnerabilities, generates a 
consolidated report, and emails the summary to subscribers.

The benefits of moving to the cloud are often so tangible and exciting that security and efficiency take a back seat many times. CRAWS aims to automate
these aspects by providing continuous monitoring and assurance of our AWS infrastructure.

CRAWS is architected as a comprehensive rules engine, with a growing collection of independent, pluggable, and configurable compliance rules. These
rules automate the tedious task of ensuring our cloud infrastructure remains reliable, scalable, efficient and secure.

## CRAWS Architecture

CRAWS is designed as a very decentralized tool, with independent, pluggable, and configurable compliance rules implemented as AWS Lambda
functions. Functionality and data elements common to all rules are contained in CRAWS core module (craws.py). Every rule runs at a predefined time
everyday and uploads its findings in json format to an s3 bucket ('craws'). There are two other centralized modules:
- **Report Generator**: Collates the findings of all the rules, creates a detailed report web page for every account, and uploads it to the same s3
bucket.
- **Email Sender**: Creates a dashboard style summary of the findings for every account and emails it to the subscribers of respective accounts.

Both of these modules also depend on the core module, which in turn uses a library 'json2html' to convert json result files to html tables.

## CRAWS S3 Bucket:

The CRAWS s3 bucket (https://s3.console.aws.amazon.com/s3/buckets/craws/?region=us-east-1) has the following structure:

A new folder is created for every date under which, every AWS account has a sub-folder. Sub-folders contain all the json result files coming from all the
rules, as well as the consolidated Result.html file.

## CRAWS Core Module:

The core module has the following attributes:
- `bucket`: 
Name of the bucket in s3 that stores all the results
- `accounts`
: Accounts that CRAWS has to analyze. It has the following structure:
```json
[
  {
    "account_id": "string",
    "display_name": "string",
    "role_arn":"string",
    "emails": ["list"]
  },
]
```
**display_name**: The common name this account is referred to as.

**role_arn**: The role that will be used to run the analysis. This role should have read access in its account and should have the role crawsExecution
(arn:aws:iam::926760075421:role/crawsExecution) as a trusted entity.

**emails**: Recipients of the report. It's a list of comma separated values.
- `status`:
Traffic light symbols used to show against the results of every region. It can have one of the following values:
    - **Red**: Issues - Critical
    - **Orange**: Issues - Medium
    - **Yellow**: Issues - Minor
    - **Green**: No Issues
    - **Grey**: Not Checked

If the check did not run for a region due to an exception, mark that region as 'Grey' during the exception handling.

The core module has the following important actions:
- `get_account_name()`
Get the display name of the account.
- `get_region_descriptions()`
Get a list of human-readable names for all the AWS regions.

Response Syntax:
```jsonc
[
  {
    "Id": "string", # Region Id
    "FullName": "string", # Full descriptive name
    "ShortName": "string" # City/State name of the region
  },
]
```
- `get_logger(name='', level='DEBUG')`
Get the Python logger. By default, the level is set to DEBUG but can be changed as needed.
    - **name**: Set it to the filename you are calling it from
    - **level**: Text logging level for the message ('DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL')
- `upload_result_json(result, file_name, account_id)`
Upload the check result json file to the s3 bucket. It creates a folder for today's date, creates a sub-folder for the account id
- `get_cloudtrail_data(lookup_value, cloudtrail_client, region_id='us-east-1')`
Get CloudTrail data for the item. Creates a summary to be shown in tooltip and a link to the CloudTrail event log. The returned value should replace
the lookup value in the calling function (since it anyways returns the original lookup value in case there are no CloudTrail logs).
    - **lookup_value**: The Id/name of the resource to be looked up
    - **cloudtrail_client**: CloudTrail client for the account containing the resource
    - **region_id**: Region Id of the resource, defaults to 'us-east-1' for global resources
