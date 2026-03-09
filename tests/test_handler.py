"""
test_handler.py - Unit Tests for IAM Guardrail Solution

Tests cover:
- handler.py  : event parsing, allowlist, orchestration
- enforcer.py : boundary attachment, role deletion
- auditor.py  : DynamoDB audit writes
"""

import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock


# -------------------------------------------------------
# HANDLER TESTS
# -------------------------------------------------------
class TestHandler:

    def test_allowlisted_role_is_skipped(self, sample_create_role_event):
        """Roles with allowlisted prefixes should be skipped."""
        sample_create_role_event["detail"]["requestParameters"]["roleName"] = "AWSServiceRole-test"
        from handler import lambda_handler
        result = lambda_handler(sample_create_role_event, {})
        assert result["statusCode"] == 200
        assert "allowlisted" in result["body"].lower()

    def test_missing_role_name_is_skipped(self, sample_create_role_event):
        """Events with no role name should be skipped gracefully."""
        sample_create_role_event["detail"]["requestParameters"] = {}
        from handler import lambda_handler
        result = lambda_handler(sample_create_role_event, {})
        assert result["statusCode"] == 200
        assert "skipped" in result["body"].lower()

    def test_principal_extracted_for_iam_user(self, sample_create_role_event):
        """IAM user principal should be extracted correctly."""
        from handler import _extract_principal
        identity = {"type": "IAMUser", "userName": "john.doe"}
        assert _extract_principal(identity) == "john.doe"

    def test_principal_extracted_for_assumed_role(self):
        """Assumed role session name should be extracted as principal."""
        from handler import _extract_principal
        identity = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/dev-role/john.doe"
        }
        assert _extract_principal(identity) == "john.doe"

    def test_root_user_flagged_as_critical(self):
        """Root user should be flagged with CRITICAL label."""
        from handler import _extract_principal
        identity = {"type": "Root"}
        assert "CRITICAL" in _extract_principal(identity)

    def test_is_allowlisted_returns_true_for_service_role(self):
        """AWSServiceRole prefix should be allowlisted."""
        from handler import _is_allowlisted
        assert _is_allowlisted("AWSServiceRole-ec2") is True

    def test_is_allowlisted_returns_false_for_regular_role(self):
        """Regular dev role should not be allowlisted."""
        from handler import _is_allowlisted
        assert _is_allowlisted("my-app-role") is False


# -------------------------------------------------------
# ENFORCER TESTS
# -------------------------------------------------------
class TestEnforcer:

    def test_boundary_attached_successfully(self, iam_client):
        """Boundary should be attached to role with no existing boundary."""
        from enforcer import enforce_boundary
        result = enforce_boundary(
            role_name="test-role",
            account_id="123456789012",
            event_name="CreateRole"
        )
        assert result["action"] == "BOUNDARY_ATTACHED"
        assert result["status"] == "SUCCESS"

    def test_skipped_if_boundary_already_present(self, iam_client):
        """Enforcement should be skipped if boundary already attached."""
        import os
        # Attach boundary first
        iam_client.put_role_permissions_boundary(
            RoleName="test-role",
            PermissionsBoundary=os.environ["BOUNDARY_POLICY_ARN"]
        )
        from enforcer import enforce_boundary
        result = enforce_boundary(
            role_name="test-role",
            account_id="123456789012",
            event_name="CreateRole"
        )
        assert result["action"] == "SKIPPED"

    def test_skipped_if_role_not_found(self, iam_client):
        """Should return SKIPPED gracefully if role doesn't exist."""
        from enforcer import enforce_boundary
        result = enforce_boundary(
            role_name="non-existent-role",
            account_id="123456789012",
            event_name="CreateRole"
        )
        assert result["action"] == "SKIPPED"


# -------------------------------------------------------
# AUDITOR TESTS
# -------------------------------------------------------
class TestAuditor:

    def test_audit_record_written_to_dynamodb(self, dynamodb_table):
        """Audit record should be written with all required fields."""
        from auditor import write_audit_record
        write_audit_record(
            account_id="123456789012",
            role_name="test-role",
            principal="john.doe",
            event_name="CreateRole",
            region="us-east-1",
            action_taken="BOUNDARY_ATTACHED",
            status="SUCCESS",
            detail="boundary arn"
        )
        response = dynamodb_table.query(
            KeyConditionExpression="accountId = :aid",
            ExpressionAttributeValues={":aid": "123456789012"}
        )
        assert len(response["Items"]) == 1
        assert response["Items"][0]["roleName"] == "test-role"
        assert response["Items"][0]["actionTaken"] == "BOUNDARY_ATTACHED"

    def test_audit_failure_does_not_raise(self):
        """Audit write failure should log error but not raise exception."""
        with patch("auditor.dynamodb") as mock_dynamo:
            mock_dynamo.Table.return_value.put_item.side_effect = Exception("DynamoDB error")
            from auditor import write_audit_record
            # Should not raise
            write_audit_record("123", "role", "user", "CreateRole", "us-east-1", "BOUNDARY_ATTACHED", "SUCCESS")