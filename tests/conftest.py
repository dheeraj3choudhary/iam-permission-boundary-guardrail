"""
conftest.py - Pytest Fixtures and Moto AWS Mocks

Provides reusable fixtures for all test files.
Uses moto to mock AWS services - no real AWS calls made during tests.
"""

import os
import json
import pytest
import boto3
from moto import mock_aws

# -------------------------------------------------------
# SET DUMMY ENV VARS BEFORE ANY IMPORTS
# -------------------------------------------------------
os.environ["ENVIRONMENT"]           = "test"
os.environ["AUDIT_TABLE_NAME"]      = "iam-guardrail-audit-test"
os.environ["ALERT_TOPIC_ARN"]       = "arn:aws:sns:us-east-1:123456789012:iam-guardrail-alerts-test"
os.environ["BOUNDARY_POLICY_ARN"]   = "arn:aws:iam::123456789012:policy/iam-guardrail-permission-boundary-test"
os.environ["TEAMS_WEBHOOK_PARAM"]   = "/iam-guardrail/test/teams-webhook-url"
os.environ["ALLOWLIST_PREFIXES"]    = "iam-guardrail-,AWSServiceRole,OrganizationAccountAccessRole"

ACCOUNT_ID      = "123456789012"
REGION          = "us-east-1"
BOUNDARY_ARN    = os.environ["BOUNDARY_POLICY_ARN"]
AUDIT_TABLE     = os.environ["AUDIT_TABLE_NAME"]


@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials so moto doesn't hit real AWS."""
    os.environ["AWS_ACCESS_KEY_ID"]     = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"]    = "testing"
    os.environ["AWS_SESSION_TOKEN"]     = "testing"
    os.environ["AWS_DEFAULT_REGION"]    = REGION


@pytest.fixture
def iam_client(aws_credentials):
    """Mocked IAM client with a test role and boundary policy."""
    with mock_aws():
        client = boto3.client("iam", region_name=REGION)

        # Create boundary policy
        client.create_policy(
            PolicyName="iam-guardrail-permission-boundary-test",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )

        # Create a test role without boundary
        client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
        )

        yield client


@pytest.fixture
def dynamodb_table(aws_credentials):
    """Mocked DynamoDB audit table."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[
                {"AttributeName": "accountId", "KeyType": "HASH"},
                {"AttributeName": "timestamp",  "KeyType": "RANGE"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "accountId", "AttributeType": "S"},
                {"AttributeName": "timestamp",  "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()
        yield table


@pytest.fixture
def sample_create_role_event():
    """Sample EventBridge event for CreateRole."""
    return {
        "detail": {
            "eventName": "CreateRole",
            "awsRegion": REGION,
            "recipientAccountId": ACCOUNT_ID,
            "requestParameters": {"roleName": "test-role"},
            "userIdentity": {
                "type": "IAMUser",
                "userName": "john.doe"
            }
        }
    }


@pytest.fixture
def sample_attach_policy_event():
    """Sample EventBridge event for AttachRolePolicy."""
    return {
        "detail": {
            "eventName": "AttachRolePolicy",
            "awsRegion": REGION,
            "recipientAccountId": ACCOUNT_ID,
            "requestParameters": {
                "roleName": "test-role",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "userIdentity": {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/dev-role/john.doe"
            }
        }
    }