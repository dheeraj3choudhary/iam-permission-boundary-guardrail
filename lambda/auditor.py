"""
auditor.py - DynamoDB Audit Trail

Writes enforcement action records to DynamoDB.
Every boundary attachment or role deletion is recorded.
"""

import os
import logging
import boto3
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AUDIT_TABLE_NAME = os.environ.get("AUDIT_TABLE_NAME")

dynamodb = boto3.resource("dynamodb")


def write_audit_record(
    account_id: str,
    role_name: str,
    principal: str,
    event_name: str,
    region: str,
    action_taken: str,
    status: str,
    detail: str = ""
) -> None:
    """Write enforcement action to DynamoDB audit table."""
    try:
        table = dynamodb.Table(AUDIT_TABLE_NAME)
        timestamp = datetime.now(timezone.utc).isoformat()

        table.put_item(Item={
            "accountId":   account_id,
            "timestamp":   timestamp,
            "roleName":    role_name,
            "principal":   principal,
            "eventName":   event_name,
            "region":      region,
            "actionTaken": action_taken,
            "status":      status,
            "detail":      detail,
            "ttl":         int(time.time()) + (365 * 24 * 60 * 60)  # 1 year TTL
        })

        logger.info(f"Audit record written for {role_name} - {action_taken}")

    except ClientError as e:
        # Log but don't raise - audit failure should not block enforcement
        logger.error(f"Failed to write audit record: {str(e)}")