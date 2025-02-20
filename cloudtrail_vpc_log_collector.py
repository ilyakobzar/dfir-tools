# CloudTrail and VPC logs collector. Outputs the data into CSV files

import boto3
import csv
import json
from datetime import datetime, timezone, timedelta
import os

def setup_aws_session(profile_name):
    return boto3.Session(profile_name=profile_name)

def collect_cloudtrail_logs(session, start_time, end_time):
    cloudtrail = session.client('cloudtrail')
    logs = []
    
    try:
        response = cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        logs.extend(response['Events'])
        
        while 'NextToken' in response:
            response = cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                NextToken=response['NextToken'],
                MaxResults=50
            )
            logs.extend(response['Events'])
    
    except Exception as e:
        print(f"Error collecting CloudTrail logs: {e}")
    
    return logs

def collect_vpc_flow_logs(session, log_group_name, start_time, end_time):
    logs_client = session.client('logs')
    flow_logs = []
    
    try:
        response = logs_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True
        )
        
        for stream in response['logStreams']:
            logs = logs_client.get_log_events(
                logGroupName=log_group_name,
                logStreamName=stream['logStreamName'],
                startTime=int(start_time.timestamp() * 1000),
                endTime=int(end_time.timestamp() * 1000)
            )
            flow_logs.extend(logs['events'])
            
    except Exception as e:
        print(f"Error collecting VPC Flow logs: {e}")
    
    return flow_logs

def save_logs_to_csv(logs, filename, log_type):
    if not logs:
        print(f"No {log_type} logs to save")
        return

    if log_type == 'cloudtrail':
        # Get all unique fields from all events
        fieldnames = set()
        for event in logs:
            # Add all top-level fields
            fieldnames.update(event.keys())
            # Add all fields from CloudTrailEvent
            if 'CloudTrailEvent' in event:
                try:
                    cloudtrail_event = json.loads(event['CloudTrailEvent'])
                    fieldnames.update(f"CloudTrailEvent_{k}" for k in cloudtrail_event.keys())
                except:
                    pass
        
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in logs:
                row = event.copy()
                # Extract CloudTrailEvent fields if present
                if 'CloudTrailEvent' in event:
                    try:
                        cloudtrail_event = json.loads(event['CloudTrailEvent'])
                        row.update({f"CloudTrailEvent_{k}": v for k, v in cloudtrail_event.items()})
                    except:
                        pass
                writer.writerow(row)
    
    elif log_type == 'vpc_flow':
        # Get all unique fields from all events
        fieldnames = set()
        for event in logs:
            fieldnames.update(event.keys())
            # Parse message field if it contains VPC Flow Log format
            if 'message' in event:
                try:
                    # VPC Flow Log fields
                    vpc_fields = ['version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr', 
                                'srcport', 'dstport', 'protocol', 'packets', 'bytes', 'start', 
                                'end', 'action', 'log-status']
                    message_parts = event['message'].split(' ')
                    if len(message_parts) >= len(vpc_fields):
                        fieldnames.update(f"vpc_{field}" for field in vpc_fields)
                except:
                    pass
        
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in logs:
                row = event.copy()
                # Parse message field if it contains VPC Flow Log format
                if 'message' in event:
                    try:
                        vpc_fields = ['version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr', 
                                    'srcport', 'dstport', 'protocol', 'packets', 'bytes', 'start', 
                                    'end', 'action', 'log-status']
                        message_parts = event['message'].split(' ')
                        if len(message_parts) >= len(vpc_fields):
                            row.update({f"vpc_{field}": value for field, value in zip(vpc_fields, message_parts)})
                    except:
                        pass
                writer.writerow(row)

def main():
    profile_name = '' # Specify profile that will be used to retrieve the logs
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=2)
    
    output_dir = 'aws_logs_' + datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(output_dir, exist_ok=True)
    
    session = setup_aws_session(profile_name)
    
    print("Collecting CloudTrail logs...")
    cloudtrail_logs = collect_cloudtrail_logs(session, start_time, end_time)
    save_logs_to_csv(cloudtrail_logs, f'{output_dir}/cloudtrail_logs.csv', 'cloudtrail')
    
    print("Collecting VPC Flow logs...")
    vpc_flow_logs = collect_vpc_flow_logs(session, 'vpc-flow-logs-for-research', start_time, end_time)
    save_logs_to_csv(vpc_flow_logs, f'{output_dir}/vpc_flow_logs.csv', 'vpc_flow')
    
    print(f"\nLogs have been saved to directory: {output_dir}")
    print(f"CloudTrail events collected: {len(cloudtrail_logs)}")
    print(f"VPC Flow log events collected: {len(vpc_flow_logs)}")

if __name__ == "__main__":
    main()