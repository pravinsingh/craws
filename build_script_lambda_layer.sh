aws lambda publish-layer-version --layer-name test-layer --description "Test Layer" --content S3Bucket=codebuild-eu-ireland-lambda-rules,S3Key=zip-files/layer.zip --compatible-runtimes python2.7 python3.6 python3.7
var=$(aws lambda list-layer-versions --layer-name test-layer --region eu-west-1 --query 'LayerVersions[0].LayerVersionArn' --output text)
aws lambda get-function --function-name craws-cloudtrail-log-status
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-cloudtrail-log-status --zip-file fileb://~/Downloads/cloudtrail_logging_status.zip
	aws lambda update-function-configuration --function-name craws-cloudtrail-log-status --layers "${var}"
else
   	aws lambda create-function --function-name craws-cloudtrail-log-status --runtime python3.7 --handler cloudtrail_logging_status.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/cloudtrail_logging_status.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-unrestricted-access
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unrestricted-access --zip-file fileb://~/Downloads/unrestricted_security_groups.zip
	aws lambda update-function-configuration --function-name craws-unrestricted-access --layers "${var}"
else
   	aws lambda create-function --function-name craws-unrestricted-access --runtime python3.7 --handler unrestricted_security_groups.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unrestricted_security_groups.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-s3-public-read-acp
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-read-acp --zip-file fileb://~/Downloads/s3_public_read_acp.zip
	aws lambda update-function-configuration --function-name craws-s3-public-read-acp --layers "${var}"
else
   	aws lambda create-function --function-name craws-s3-public-read-acp --runtime python3.7 --handler s3_public_read_acp.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_read_acp.zip --layers "${var}"
fi
aws lambda get-function --function-name craws-mfa-not-enabled
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-mfa-not-enabled --zip-file fileb://~/Downloads/mfa_not_enabled.zip
	aws lambda update-function-configuration --function-name craws-mfa-not-enabled --layers "${var}"
else
   	aws lambda create-function --function-name craws-mfa-not-enabled --runtime python3.7 --handler mfa_not_enabled.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/mfa_not_enabled.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-ec2-maintenance
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-ec2-maintenance --zip-file fileb://~/Downloads/ec2_maintenance_events.zip
	aws lambda update-function-configuration --function-name craws-ec2-maintenance --layers "${var}"
else
   	aws lambda create-function --function-name craws-ec2-maintenance --runtime python3.7 --handler ec2_maintenance_events.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/ec2_maintenance_events.zip --layers "${var}"
fi
aws lambda get-function --function-name craws-email-results
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-email-results --zip-file fileb://~/Downloads/email_results.zip
	aws lambda update-function-configuration --function-name craws-email-results --layers "${var}"
else
   	aws lambda create-function --function-name craws-email-results --runtime python3.7 --handler email_results.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/email_results.zip --layers "${var}"
fi
aws lambda get-function --function-name craws-default-vpc-in-use
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-default-vpc-in-use --zip-file fileb://~/Downloads/default_vpc_in_use.zip
	aws lambda update-function-configuration --function-name craws-default-vpc-in-use --layers "${var}"
else
   	aws lambda create-function --function-name craws-default-vpc-in-use --runtime python3.7 --handler default_vpc_in_use.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/default_vpc_in_use.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-disabled-cloudtrail
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-disabled-cloudtrail --zip-file fileb://~/Downloads/disabled_cloudtrail.zip
	aws lambda update-function-configuration --function-name craws-disabled-cloudtrail --layers "${var}"
else
   	aws lambda create-function --function-name craws-disabled-cloudtrail --runtime python3.7 --handler disabled_cloudtrail.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/disabled_cloudtrail.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-rds-with-byol
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-byol --zip-file fileb://~/Downloads/rds_with_byol.zip
	aws lambda update-function-configuration --function-name craws-rds-with-byol --layers "${var}"
else
   	aws lambda create-function --function-name craws-rds-with-byol --runtime python3.7 --handler rds_with_byol.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_byol.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-iam-certificate-expiry
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-iam-certificate-expiry --zip-file fileb://~/Downloads/iam_cert_expiry_check.zip
	aws lambda update-function-configuration --function-name craws-iam-certificate-expiry --layers "${var}"
else
   	aws lambda create-function --function-name craws-iam-certificate-expiry --runtime python3.7 --handler iam_cert_expiry_check.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/iam_cert_expiry_check.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-s3-public-write-acp
if [ 0 -eq $? ]; then	
	aws lambda update-function-code --function-name craws-s3-public-write-acp --zip-file fileb://~/Downloads/s3_public_write_acp.zip
	aws lambda update-function-configuration --function-name craws-s3-public-write-acp --layers "${var}"
else
   	aws lambda create-function --function-name craws-s3-public-write-acp --runtime python3.7 --handler s3_public_write_acp.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_write_acp.zip --layers "${var}"
fi
aws lambda get-function --function-name craws-RDS-in-public-subnet
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-RDS-in-public-subnet --zip-file fileb://~/Downloads/rds_instance_in_public_subnet.zip
	aws lambda update-function-configuration --function-name craws-RDS-in-public-subnet --layers "${var}"
else
   	aws lambda create-function --function-name craws-RDS-in-public-subnet --runtime python3.7 --handler rds_instance_in_public_subnet.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_instance_in_public_subnet.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-rds-with-multiAZ-disabled
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-multiAZ-disabled --zip-file fileb://~/Downloads/rds_with_multiaz_disabled.zip
	aws lambda update-function-configuration --function-name craws-rds-with-multiAZ-disabled --layers "${var}"
else
   	aws lambda create-function --function-name craws-rds-with-multiAZ-disabled --runtime python3.7 --handler rds_with_multiaz_disabled.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_multiaz_disabled.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-rds-with-magnetic-storage-type
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-rds-with-magnetic-storage-type --zip-file fileb://~/Downloads/rds_with_magnetic_storage.zip
	aws lambda update-function-configuration --function-name craws-rds-with-magnetic-storage-type --layers "${var}"
else
   	aws lambda create-function --function-name craws-rds-with-magnetic-storage-type --runtime python3.7 --handler rds_with_magnetic_storage.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_with_magnetic_storage.zip --layers "${var}"
fi
aws lambda get-function --function-name craws-account-password-policy
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-account-password-policy --zip-file fileb://~/Downloads/password_policy.zip
	aws lambda update-function-configuration --function-name craws-account-password-policy --layers "${var}"
else
   	aws lambda create-function --function-name craws-account-password-policy --runtime python3.7 --handler password_policy.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/password_policy.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-unused-access-keys
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-access-keys --zip-file fileb://~/Downloads/unused_access_keys.zip
	aws lambda update-function-configuration --function-name craws-unused-access-keys --layers "${var}"
else
   	aws lambda create-function --function-name craws-unused-access-keys --runtime python3.7 --handler unused_access_keys.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_access_keys.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-ec2-instances-distribution
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-ec2-instances-distribution --zip-file fileb://~/Downloads/ec2_instances_distribution.zip
	aws lambda update-function-configuration --function-name craws-ec2-instances-distribution --layers "${var}"
else
   	aws lambda create-function --function-name craws-ec2-instances-distribution --runtime python3.7 --handler ec2_instances_distribution.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/ec2_instances_distribution.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-unused-rds
if [ 0 -eq $? ]; then	
	aws lambda update-function-code --function-name craws-unused-rds --zip-file fileb://~/Downloads/unused_rds.zip
	aws lambda update-function-configuration --function-name craws-unused-rds --layers "${var}"
else
   	aws lambda create-function --function-name craws-unused-rds --runtime python3.7 --handler unused_rds.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_rds.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-disabled-automated-rds-backup
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-disabled-automated-rds-backup --zip-file fileb://~/Downloads/rds_disabled_backup.zip
	aws lambda update-function-configuration --function-name craws-disabled-automated-rds-backup --layers "${var}"
else
   	aws lambda create-function --function-name craws-disabled-automated-rds-backup --runtime python3.7 --handler rds_disabled_backup.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/rds_disabled_backup.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-acm-certificate-expiry
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-acm-certificate-expiry --zip-file fileb://~/Downloads/acm_cert_expiry_check.zip
	aws lambda update-function-configuration --function-name craws-acm-certificate-expiry --layers "${var}"
else
   	aws lambda create-function --function-name craws-acm-certificate-expiry --runtime python3.7 --handler acm_cert_expiry_check.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/acm_cert_expiry_check.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-generate-reports
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-generate-reports --zip-file fileb://~/Downloads/generate_reports.zip
	aws lambda update-function-configuration --function-name craws-generate-reports --layers "${var}"
else
   	aws lambda create-function --function-name craws-generate-reports --runtime python3.7 --handler generate_reports.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/generate_reports.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-multiple-access-keys
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-multiple-access-keys --zip-file fileb://~/Downloads/multiple_access_keys.zip
	aws lambda update-function-configuration --function-name craws-multiple-access-keys --layers "${var}"
else
   	aws lambda create-function --function-name craws-multiple-access-keys --runtime python3.7 --handler multiple_access_keys.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/multiple_access_keys.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-default-SG-inuse
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-default-SG-inuse --zip-file fileb://~/Downloads/default_sg_in_use.zip
	aws lambda update-function-configuration --function-name craws-default-SG-inuse --layers "${var}"
else
   	aws lambda create-function --function-name craws-default-SG-inuse --runtime python3.7 --handler default_sg_in_use.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/default_sg_in_use.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-s3-public-list
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-list --zip-file fileb://~/Downloads/s3_public_list.zip
	aws lambda update-function-configuration --function-name craws-s3-public-list --layers "${var}"
else
   	aws lambda create-function --function-name craws-s3-public-list --runtime python3.7 --handler s3_public_list.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_list.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-access-keys-not-rotated
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-access-keys-not-rotated --zip-file fileb://~/Downloads/access_keys_not_rotated.zip
	aws lambda update-function-configuration --function-name craws-access-keys-not-rotated --layers "${var}"
else
   	aws lambda create-function --function-name craws-access-keys-not-rotated --runtime python3.7 --handler access_keys_not_rotated.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/access_keys_not_rotated.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-unused-security-groups
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-security-groups --zip-file fileb://~/Downloads/unused_security_groups.zip
	aws lambda update-function-configuration --function-name craws-unused-security-groups --layers "${var}"
else
   	aws lambda create-function --function-name craws-unused-security-groups --runtime python3.7 --handler unused_security_groups.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_security_groups.zip --layers "${var}" 
fi
aws lambda get-function --function-name craws-s3-public-write
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-s3-public-write --zip-file fileb://~/Downloads/s3_public_write.zip
	aws lambda update-function-configuration --function-name craws-s3-public-write --layers "${var}"
else
   	aws lambda create-function --function-name craws-s3-public-write --runtime python3.7 --handler s3_public_write.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/s3_public_write.zip --layers "${var}"  
fi
aws lambda get-function --function-name craws-unused-elastic-ips
if [ 0 -eq $? ]; then
	aws lambda update-function-code --function-name craws-unused-elastic-ips --zip-file fileb://~/Downloads/unused_elastic_ips.zip
	aws lambda update-function-configuration --function-name craws-unused-elastic-ips --layers "${var}"
else
   	aws lambda create-function --function-name craws-unused-elastic-ips --runtime python3.7 --handler unused_elastic_ips.handler --role arn:aws:iam::926760075421:role/crawsExecution --memory-size 128 --timeout 15 --description LambdaFunction --zip-file fileb://~/Downloads/unused_elastic_ips.zip --layers "${var}"  
fi

