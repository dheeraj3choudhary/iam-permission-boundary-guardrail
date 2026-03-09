"""
notifier.py - Microsoft Teams Notification

Sends enforcement alerts to Teams security channel
via incoming webhook using Adaptive Card format.
"""

import os
import json
import logging
import boto3
import urllib.request
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TEAMS_WEBHOOK_PARAM = os.environ.get("TEAMS_WEBHOOK_PARAM")

ssm = boto3.client("ssm")


def send_teams_notification(
    account_id: str,
    role_name: str,
    principal: str,
    event_name: str,
    region: str,
    action_taken: str,
    status: str
) -> None:
    """Send enforcement alert to Teams security channel."""
    try:
        webhook_url = _get_webhook_url()
        card = _build_adaptive_card(
            account_id, role_name, principal,
            event_name, region, action_taken, status
        )
        _post_to_teams(webhook_url, card)

    except Exception as e:
        # Log but don't raise - notification failure should not block enforcement
        logger.error(f"Failed to send Teams notification: {str(e)}")


def _get_webhook_url() -> str:
    """Fetch Teams webhook URL from SSM Parameter Store."""
    response = ssm.get_parameter(Name=TEAMS_WEBHOOK_PARAM, WithDecryption=True)
    return response["Parameter"]["Value"]


def _build_adaptive_card(
    account_id, role_name, principal,
    event_name, region, action_taken, status
) -> dict:
    """Build Teams Adaptive Card payload."""
    color = "attention" if action_taken == "ROLE_DELETED" else "warning" if action_taken == "BOUNDARY_ATTACHED" else "good"
    emoji = "🔴" if action_taken == "ROLE_DELETED" else "🟡" if action_taken == "BOUNDARY_ATTACHED" else "✅"

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"{emoji} IAM Guardrail Alert - {action_taken}",
                        "weight": "Bolder",
                        "size": "Medium",
                        "color": color
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Account ID",    "value": account_id},
                            {"title": "Role Name",     "value": role_name},
                            {"title": "Triggered By",  "value": principal},
                            {"title": "IAM Event",     "value": event_name},
                            {"title": "Region",        "value": region},
                            {"title": "Action Taken",  "value": action_taken},
                            {"title": "Status",        "value": status}
                        ]
                    }
                ]
            }
        }]
    }


def _post_to_teams(webhook_url: str, card: dict) -> None:
    """POST Adaptive Card to Teams webhook."""
    data = json.dumps(card).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as response:
        logger.info(f"Teams notification sent - status: {response.status}")