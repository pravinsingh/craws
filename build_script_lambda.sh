aws lambda get-function --function-name craws-cloudtrail-log-status
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-cloudtrail-log-status --zip-file fileb://~/Downloads/cloudtrail_logging_status.zip
else
   	aws lambda create-function --function-name craws-cloudtrail-log-status --runtime python3.7 --handler cloudtrail_logging_status.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/cloudtrail_logging_status.zip  
fi
aws lambda get-function --function-name craws-unrestricted-access
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unrestricted-access --zip-file fileb://~/Downloads/unrestricted_security_groups.zip
else
   	aws lambda create-function --function-name craws-unrestricted-access --runtime python3.7 --handler unrestricted_security_groups.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unrestricted_security_groups.zip  
fi
aws lambda get-function --function-name craws-s3-public-read-acp
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-read-acp --zip-file fileb://~/Downloads/s3_public_read_acp.zip
else
   	aws lambda create-function --function-name craws-s3-public-read-acp --runtime python3.7 --handler s3_public_read_acp.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_read_acp.zip  
fi
aws lambda get-function --function-name craws-mfa-not-enabled
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-mfa-not-enabled --zip-file fileb://~/Downloads/mfa_not_enabled.zip
else
   	aws lambda create-function --function-name craws-mfa-not-enabled --runtime python3.7 --handler mfa_not_enabled.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/mfa_not_enabled.zip  
fi
aws lambda get-function --function-name craws-ec2-maintenance
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-ec2-maintenance --zip-file fileb://~/Downloads/ec2_maintenance_events.zip
else
   	aws lambda create-function --function-name craws-ec2-maintenance --runtime python3.7 --handler ec2_maintenance_events.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/ec2_maintenance_events.zip  
fi
aws lambda get-function --function-name craws-email-results
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-email-results --zip-file fileb://~/Downloads/email_results.zip
else
   	aws lambda create-function --function-name craws-email-results --runtime python3.7 --handler email_results.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/email_results.zip  
fi
aws lambda get-function --function-name craws-default-vpc-in-use
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-default-vpc-in-use --zip-file fileb://~/Downloads/default_vpc_in_use.zip
else
   	aws lambda create-function --function-name craws-default-vpc-in-use --runtime python3.7 --handler default_vpc_in_use.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/default_vpc_in_use.zip  
fi
aws lambda get-function --function-name craws-disabled-cloudtrail
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-disabled-cloudtrail --zip-file fileb://~/Downloads/disabled_cloudtrail.zip
else
   	aws lambda create-function --function-name craws-disabled-cloudtrail --runtime python3.7 --handler disabled_cloudtrail.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/disabled_cloudtrail.zip  
fi
aws lambda get-function --function-name craws-rds-with-byol
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-byol --zip-file fileb://~/Downloads/rds_with_byol.zip
else
   	aws lambda create-function --function-name craws-rds-with-byol --runtime python3.7 --handler rds_with_byol.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_byol.zip  
fi
aws lambda get-function --function-name craws-iam-certificate-expiry
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-iam-certificate-expiry --zip-file fileb://~/Downloads/iam_cert_expiry_check.zip
else
   	aws lambda create-function --function-name craws-iam-certificate-expiry --runtime python3.7 --handler iam_cert_expiry_check.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/iam_cert_expiry_check.zip  
fi
aws lambda get-function --function-name craws-s3-public-write-acp
if [ 0 -eq $? ]; then	
	aws lambda update-function-code --function-name craws-s3-public-write-acp --zip-file fileb://~/Downloads/s3_public_write_acp.zip
else
   	aws lambda create-function --function-name craws-s3-public-write-acp --runtime python3.7 --handler s3_public_write_acp.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_write_acp.zip  
fi
aws lambda get-function --function-name craws-RDS-in-public-subnet
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-RDS-in-public-subnet --zip-file fileb://~/Downloads/rds_instance_in_public_subnet.zip
else
   	aws lambda create-function --function-name craws-RDS-in-public-subnet --runtime python3.7 --handler rds_instance_in_public_subnet.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_instance_in_public_subnet.zip  
fi
aws lambda get-function --function-name craws-rds-with-multiAZ-disabled
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-multiAZ-disabled --zip-file fileb://~/Downloads/rds_with_multiaz_disabled.zip
else
   	aws lambda create-function --function-name craws-rds-with-multiAZ-disabled --runtime python3.7 --handler rds_with_multiaz_disabled.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_multiaz_disabled.zip  
fi
aws lambda get-function --function-name craws-rds-with-magnetic-storage-type
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-magnetic-storage-type --zip-file fileb://~/Downloads/rds_with_magnetic_storage.zip
else
   	aws lambda create-function --function-name craws-rds-with-magnetic-storage-type --runtime python3.7 --handler rds_with_magnetic_storage.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_magnetic_storage.zip  
fi
aws lambda get-function --function-name craws-account-password-policy
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-account-password-policy --zip-file fileb://~/Downloads/password_policy.zip
else
   	aws lambda create-function --function-name craws-account-password-policy --runtime python3.7 --handler password_policy.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/password_policy.zip  
fi
aws lambda get-function --function-name craws-unused-access-keys
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-access-keys --zip-file fileb://~/Downloads/unused_access_keys.zip
else
   	aws lambda create-function --function-name craws-unused-access-keys --runtime python3.7 --handler unused_access_keys.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_access_keys.zip  
fi
aws lambda get-function --function-name craws-ec2-instances-distribution
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-ec2-instances-distribution --zip-file fileb://~/Downloads/ec2_instances_distribution.zip
else
   	aws lambda create-function --function-name craws-ec2-instances-distribution --runtime python3.7 --handler ec2_instances_distribution.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/ec2_instances_distribution.zip  
fi
aws lambda get-function --function-name craws-unused-rds
if [ 0 -eq $? ]; then	
	aws lambda update-function-code --function-name craws-unused-rds --zip-file fileb://~/Downloads/unused_rds.zip
else
   	aws lambda create-function --function-name craws-unused-rds --runtime python3.7 --handler unused_rds.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_rds.zip  
fi
aws lambda get-function --function-name craws-disabled-automated-rds-backup
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-disabled-automated-rds-backup --zip-file fileb://~/Downloads/rds_disabled_backup.zip
else
   	aws lambda create-function --function-name craws-disabled-automated-rds-backup --runtime python3.7 --handler rds_disabled_backup.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_disabled_backup.zip  
fi
aws lambda get-function --function-name craws-acm-certificate-expiry
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-acm-certificate-expiry --zip-file fileb://~/Downloads/acm_cert_expiry_check.zip
else
   	aws lambda create-function --function-name craws-acm-certificate-expiry --runtime python3.7 --handler acm_cert_expiry_check.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/acm_cert_expiry_check.zip  
fi
aws lambda get-function --function-name craws-generate-reports
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-generate-reports --zip-file fileb://~/Downloads/generate_reports.zip
else
   	aws lambda create-function --function-name craws-generate-reports --runtime python3.7 --handler generate_reports.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/generate_reports.zip  
fi
aws lambda get-function --function-name craws-multiple-access-keys
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-multiple-access-keys --zip-file fileb://~/Downloads/multiple_access_keys.zip
else
   	aws lambda create-function --function-name craws-multiple-access-keys --runtime python3.7 --handler multiple_access_keys.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/multiple_access_keys.zip  
fi
aws lambda get-function --function-name craws-default-SG-inuse
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-default-SG-inuse --zip-file fileb://~/Downloads/default_sg_in_use.zip
else
   	aws lambda create-function --function-name craws-default-SG-inuse --runtime python3.7 --handler default_sg_in_use.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/default_sg_in_use.zip  
fi
aws lambda get-function --function-name craws-s3-public-list
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-list --zip-file fileb://~/Downloads/s3_public_list.zip
else
   	aws lambda create-function --function-name craws-s3-public-list --runtime python3.7 --handler s3_public_list.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_list.zip  
fi
aws lambda get-function --function-name craws-access-keys-not-rotated
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-access-keys-not-rotated --zip-file fileb://~/Downloads/access_keys_not_rotated.zip
else
   	aws lambda create-function --function-name craws-access-keys-not-rotated --runtime python3.7 --handler access_keys_not_rotated.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/access_keys_not_rotated.zip  
fi
aws lambda get-function --function-name craws-unused-security-groups
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-security-groups --zip-file fileb://~/Downloads/unused_security_groups.zip
else
   	aws lambda create-function --function-name craws-unused-security-groups --runtime python3.7 --handler unused_security_groups.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_security_groups.zip  
fi
aws lambda get-function --function-name craws-s3-public-write
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-write --zip-file fileb://~/Downloads/s3_public_write.zip
else
   	aws lambda create-function --function-name craws-s3-public-write --runtime python3.7 --handler s3_public_write.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_write.zip  
fi
aws lambda get-function --function-name craws-unused-elastic-ips
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-elastic-ips --zip-file fileb://~/Downloads/unused_elastic_ips.zip
else
   	aws lambda create-function --function-name craws-unused-elastic-ips --runtime python3.7 --handler unused_elastic_ips.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_elastic_ips.zip  
fi

