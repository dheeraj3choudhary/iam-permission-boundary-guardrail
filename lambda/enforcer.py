"""
Permission Boundary Enforcement Logic
Attaches permission boundary to IAM role.
If attachment fails, deletes the role to prevent ungoverned access.
"""

import os
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BOUNDARY_POLICY_ARN = os.environ.get("BOUNDARY_POLICY_ARN")

iam = boto3.client("iam")


def enforce_boundary(role_name: str, account_id: str, event_name: str) -> dict:
    """
    Attach permission boundary to role.
    If boundary already exists → skip.
    If attachment fails → delete role.
    """
    try:
        # Check if boundary already attached
        role = iam.get_role(RoleName=role_name)["Role"]
        existing_boundary = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")

        if existing_boundary == BOUNDARY_POLICY_ARN:
            logger.info(f"Boundary already attached to {role_name} - skipping")
            return {"action": "SKIPPED", "status": "SUCCESS", "detail": "Boundary already present"}

        # Attach boundary
        iam.put_role_permissions_boundary(
            RoleName=role_name,
            PermissionsBoundary=BOUNDARY_POLICY_ARN
        )
        logger.info(f"Boundary attached to {role_name}")
        return {"action": "BOUNDARY_ATTACHED", "status": "SUCCESS", "detail": BOUNDARY_POLICY_ARN}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchEntityException":
            logger.warning(f"Role {role_name} not found - may have been deleted already")
            return {"action": "SKIPPED", "status": "SUCCESS", "detail": "Role not found"}

        # Boundary attachment failed - delete role to prevent ungoverned access
        logger.error(f"Failed to attach boundary to {role_name}: {str(e)} - deleting role")
        return _delete_role(role_name)


def _delete_role(role_name: str) -> dict:
    """Delete role if boundary attachment fails."""
    try:
        # Detach all managed policies before deletion
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for policy in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])

        iam.delete_role(RoleName=role_name)
        logger.info(f"Role {role_name} deleted successfully")
        return {"action": "ROLE_DELETED", "status": "SUCCESS", "detail": "Boundary attach failed - role deleted"}

    except ClientError as e:
        logger.error(f"Failed to delete role {role_name}: {str(e)}")
        return {"action": "ROLE_DELETE_FAILED", "status": "FAILED", "detail": str(e)}