import boto3
import os
from datetime import datetime

iam = boto3.client("iam")

BOUNDARY_ARN = os.environ["PERMISSION_BOUNDARY"]
ALLOWLIST = os.environ["ROLE_ALLOWLIST"].split(",")


def enforce_boundary(event):

    role_name = event["detail"]["requestParameters"]["roleName"]
    creator = event["detail"]["userIdentity"]["arn"]

    timestamp = datetime.utcnow().isoformat()

    if role_name in ALLOWLIST:
        return {
            "role_name": role_name,
            "creator": creator,
            "timestamp": timestamp,
            "action": "skipped_allowlisted_role"
        }

    try:
        iam.put_role_permissions_boundary(
            RoleName=role_name,
            PermissionsBoundary=BOUNDARY_ARN
        )

        action = "boundary_attached"

    except Exception:

        iam.delete_role(RoleName=role_name)
        action = "role_deleted"

    return {
        "role_name": role_name,
        "creator": creator,
        "timestamp": timestamp,
        "action": action
    }