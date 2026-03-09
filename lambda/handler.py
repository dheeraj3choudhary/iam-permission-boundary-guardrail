"""
handler.py - IAM Guardrail Lambda Entry Point

Orchestrates the enforcement flow:
1. Parse incoming EventBridge event (CloudTrail IAM event)
2. Extract role details
3. Check against allowlist
4. Enforce permission boundary
5. Audit the action
6. Notify security team via Teams
"""

import os
import logging
from enforcer import enforce_boundary
from auditor import write_audit_record
from notifier import send_teams_notification

# -------------------------------------------------------
# LOGGER SETUP
# -------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# -------------------------------------------------------
# ENVIRONMENT VARIABLES
# Injected by CloudFormation app-stack.yml
# -------------------------------------------------------
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
ALLOWLIST_PREFIXES = os.environ.get(
    "ALLOWLIST_PREFIXES",
    "iam-guardrail-,AWSServiceRole,OrganizationAccountAccessRole"
).split(",")


# -------------------------------------------------------
# MAIN HANDLER
# -------------------------------------------------------
def lambda_handler(event, context):
    """
    Main entry point triggered by EventBridge.
    Handles three IAM events:
    - CreateRole
    - AttachRolePolicy
    - PutRolePolicy
    """
    logger.info(f"Received event: {event}")

    try:
        # --------------------------------------------------
        # STEP 1: Parse event details from CloudTrail
        # --------------------------------------------------
        event_detail = event.get("detail", {})
        event_name = event_detail.get("eventName")
        aws_region = event_detail.get("awsRegion")
        account_id = event_detail.get("recipientAccountId")
        request_params = event_detail.get("requestParameters", {})
        user_identity = event_detail.get("userIdentity", {})

        # Extract who triggered the IAM action
        principal = _extract_principal(user_identity)

        logger.info(f"Processing event: {event_name} by {principal} in account {account_id}")

        # --------------------------------------------------
        # STEP 2: Extract role name based on event type
        # --------------------------------------------------
        role_name = _extract_role_name(event_name, request_params)

        if not role_name:
            logger.warning(f"Could not extract role name from event: {event_name}")
            return _response(200, "Skipped - could not extract role name")

        # --------------------------------------------------
        # STEP 3: Check allowlist - skip platform/service roles
        # --------------------------------------------------
        if _is_allowlisted(role_name):
            logger.info(f"Role {role_name} is allowlisted - skipping enforcement")
            return _response(200, f"Skipped - role {role_name} is allowlisted")

        # --------------------------------------------------
        # STEP 4: Enforce permission boundary
        # Returns enforcement result dict with action taken
        # --------------------------------------------------
        enforcement_result = enforce_boundary(
            role_name=role_name,
            account_id=account_id,
            event_name=event_name
        )

        logger.info(f"Enforcement result: {enforcement_result}")

        # --------------------------------------------------
        # STEP 5: Write audit record to DynamoDB
        # --------------------------------------------------
        write_audit_record(
            account_id=account_id,
            role_name=role_name,
            principal=principal,
            event_name=event_name,
            region=aws_region,
            action_taken=enforcement_result["action"],
            status=enforcement_result["status"],
            detail=enforcement_result.get("detail", "")
        )

        # --------------------------------------------------
        # STEP 6: Send Teams notification to security channel
        # --------------------------------------------------
        send_teams_notification(
            account_id=account_id,
            role_name=role_name,
            principal=principal,
            event_name=event_name,
            region=aws_region,
            action_taken=enforcement_result["action"],
            status=enforcement_result["status"]
        )

        return _response(200, f"Enforcement complete: {enforcement_result['action']}")

    except Exception as e:
        logger.error(f"Unhandled exception in handler: {str(e)}", exc_info=True)
        # Re-raise so Lambda marks invocation as failed
        # This triggers the CloudWatch alarm in app-stack.yml
        raise


# -------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------
def _extract_role_name(event_name: str, request_params: dict) -> str:
    """
    Extract role name from request parameters.
    Field name differs per event type.

    CreateRole       → requestParameters.roleName
    AttachRolePolicy → requestParameters.roleName
    PutRolePolicy    → requestParameters.roleName
    """
    return request_params.get("roleName", "")


def _extract_principal(user_identity: dict) -> str:
    """
    Extract human-readable principal from CloudTrail userIdentity.
    Handles IAM users, assumed roles, and federated identities.
    """
    identity_type = user_identity.get("type", "Unknown")

    if identity_type == "IAMUser":
        return user_identity.get("userName", "Unknown IAM User")

    elif identity_type == "AssumedRole":
        # Extract username from assumed role ARN
        # arn:aws:sts::123456789:assumed-role/role-name/session-name
        arn = user_identity.get("arn", "")
        parts = arn.split("/")
        return parts[-1] if len(parts) >= 3 else arn

    elif identity_type == "FederatedUser":
        return user_identity.get("principalId", "Unknown Federated User")

    elif identity_type == "Root":
        return "ROOT USER - CRITICAL"

    else:
        return user_identity.get("principalId", f"Unknown ({identity_type})")


def _is_allowlisted(role_name: str) -> bool:
    """
    Check if role name starts with any allowlisted prefix.
    Prevents enforcement on:
    - Our own guardrail Lambda role
    - AWS service-linked roles
    - Organization account access roles
    """
    for prefix in ALLOWLIST_PREFIXES:
        if role_name.startswith(prefix.strip()):
            return True
    return False


def _response(status_code: int, message: str) -> dict:
    """Standard Lambda response format."""
    return {
        "statusCode": status_code,
        "body": message
    }