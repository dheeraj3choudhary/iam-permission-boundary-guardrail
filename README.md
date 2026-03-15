<div align="center">

# IAM Permission Boundary Guardrail
Automated enforcement of IAM permission boundaries on newly created roles in AWS accounts. Detects IAM events in real-time via CloudTrail and EventBridge, enforces boundaries instantly via Lambda, and notifies the security team via Microsoft Teams.


[![AWS](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![AWS Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=for-the-badge&logo=awslambda&logoColor=white)](https://aws.amazon.com/lambda/)
[![Amazon DynamoDB](https://img.shields.io/badge/DynamoDB-4053D6?style=for-the-badge&logo=amazondynamodb&logoColor=white)](https://aws.amazon.com/dynamodb/)
[![Amazon EventBridge](https://img.shields.io/badge/EventBridge-FF4F8B?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/eventbridge/)
[![Amazon SNS](https://img.shields.io/badge/SNS-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/sns/)
[![CloudFormation](https://img.shields.io/badge/CloudFormation-FF4F8B?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/cloudformation/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/features/actions)
[![Microsoft Teams](https://img.shields.io/badge/Microsoft_Teams-6264A7?style=for-the-badge&logo=microsoftteams&logoColor=white)](https://www.microsoft.com/en/microsoft-teams/)
[![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://pytest.org/)
[![Moto](https://img.shields.io/badge/Moto-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://docs.getmoto.org/)

<a href="https://www.buymeacoffee.com/Dheeraj3" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" height="50">
</a>

## [Subscribe](https://www.youtube.com/@dheeraj-choudhary?sub_confirmation=1) to learn more About Artificial-Intellegence, Machine-Learning, Cloud & DevOps.

<p align="center">
<a href="https://www.linkedin.com/in/dheeraj-choudhary/" target="_blank">
  <img height="100" alt="Dheeraj Choudhary | LinkedIN"  src="https://user-images.githubusercontent.com/60597290/152035581-a7c6c0c3-65c3-4160-89c0-e90ddc1e8d4e.png"/>
</a> 

<a href="https://www.youtube.com/@dheeraj-choudhary?sub_confirmation=1">
    <img height="100" src="https://user-images.githubusercontent.com/60597290/152035929-b7f75d38-e1c2-4325-a97e-7b934b8534e2.png" />
</a>    
</p>

</div>

---

## Problem Statement

SCPs handle what accounts **cannot do** at provisioning time, but once a developer is inside an account, IAM role creation has no automated guardrails. This solution fills that gap by enforcing permission boundaries on every role created post-provisioning — without modifying the existing SCP governance model.

---

## Architecture

```
Developer → CloudTrail → EventBridge → Lambda → ┬→ DynamoDB (audit trail)
                                                  └→ SNS → Teams (security channel)
```

### Monitored IAM Events
| Event | Risk |
|---|---|
| `CreateRole` | New ungoverned role created |
| `AttachRolePolicy` | Managed policy attached to role |
| `PutRolePolicy` | Inline policy added to role |

### Enforcement Actions
| Outcome | When |
|---|---|
| `BOUNDARY_ATTACHED` | Role exists, no boundary present |
| `SKIPPED` | Boundary already attached or role is allowlisted |
| `ROLE_DELETED` | Boundary attachment failed — role removed to prevent ungoverned access |

---

## Repository Structure

```
iam-guardrail/
├── .github/
│   └── workflows/
│       └── deploy.yml              # GitHub Actions CI/CD pipeline
├── cloudformation/
│   ├── core-stack.yml              # DynamoDB, SNS, IAM roles, Permission Boundary Policy
│   └── app-stack.yml               # Lambda function, EventBridge rules, CloudWatch alarm
├── lambda/
│   ├── handler.py                  # Main Lambda entry point + orchestration
│   ├── enforcer.py                 # boto3 boundary attachment / role deletion logic
│   ├── auditor.py                  # DynamoDB audit write
│   └── notifier.py                 # Microsoft Teams notification via SNS webhook
├── tests/
│   ├── conftest.py                 # Moto AWS mocks + pytest fixtures
│   └── test_handler.py             # Unit tests for all modules
├── .gitignore
└── README.md
```

---

## Infrastructure

### Core Stack (`core-stack.yml`)
Foundational resources — deployed once, rarely changed.

| Resource | Purpose |
|---|---|
| `IAMPermissionBoundaryPolicy` | Boundary policy attached to all new roles. Explicitly denies IAM privilege escalation actions |
| `AuditTable` (DynamoDB) | Audit trail for all enforcement actions. `DeletionPolicy: Retain` — survives stack deletion |
| `GuardrailAlertTopic` (SNS) | Alert channel between Lambda and Teams |
| `TeamsWebhookParameter` (SSM) | Teams webhook URL stored securely — never hardcoded |
| `LambdaExecutionRole` | Least privilege execution role for Lambda. Has its own boundary attached |

### App Stack (`app-stack.yml`)
Application resources — redeployed on every code change.

| Resource | Purpose |
|---|---|
| `GuardrailLambda` | Core enforcement engine triggered by EventBridge |
| `CreateRoleEventRule` | EventBridge rule for `CreateRole` events |
| `AttachRolePolicyEventRule` | EventBridge rule for `AttachRolePolicy` events |
| `PutRolePolicyEventRule` | EventBridge rule for `PutRolePolicy` events |
| `LambdaErrorAlarm` (CloudWatch) | Alerts if Lambda starts failing — security gap detection |

---

## Lambda Modules

### `handler.py`
Entry point. Parses CloudTrail event, extracts role name and principal, checks allowlist, then orchestrates enforcement → audit → notification.

### `enforcer.py`
Core boto3 logic. Checks if boundary already exists (idempotent), attaches boundary, or deletes role if attachment fails. Detaches all managed policies before role deletion.

### `auditor.py`
Writes enforcement record to DynamoDB with 1-year TTL. Failure never blocks enforcement.

### `notifier.py`
Fetches Teams webhook URL from SSM, builds color-coded Adaptive Card, posts to Teams security channel. Failure never blocks enforcement.

---

## Allowlisted Role Prefixes

Roles matching these prefixes are skipped to prevent infinite loops and preserve platform roles:

```
iam-guardrail-        # The guardrail Lambda's own role
AWSServiceRole        # AWS service-linked roles
OrganizationAccountAccessRole  # Cross-account org access role
```

Configurable via `AllowlistRolePrefixes` CloudFormation parameter.

---

## CI/CD Pipeline

Three jobs run sequentially on every push to `main`:

```
validate → deploy → smoke-test
```

| Job | Steps |
|---|---|
| `validate` | cfn-lint on both stacks + pytest unit tests |
| `deploy` | Deploy core-stack → Deploy app-stack → Update Lambda code |
| `smoke-test` | Verify Lambda is Active + all 3 EventBridge rules are ENABLED |

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | AWS credentials for deployment |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials for deployment |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams incoming webhook URL |

---

## Deployment

### Prerequisites
- AWS CLI configured
- Python 3.12+
- GitHub repository with secrets configured

### First Time Deployment

```bash
# Deploy core stack first
aws cloudformation deploy \
  --template-file cloudformation/core-stack.yml \
  --stack-name iam-guardrail-core-prod \
  --parameter-overrides \
      Environment=prod \
      TeamsWebhookUrl=<your-teams-webhook-url> \
      AuditTableName=iam-guardrail-audit \
  --capabilities CAPABILITY_NAMED_IAM

# Deploy app stack second (imports outputs from core stack)
aws cloudformation deploy \
  --template-file cloudformation/app-stack.yml \
  --stack-name iam-guardrail-app-prod \
  --parameter-overrides Environment=prod \
  --capabilities CAPABILITY_NAMED_IAM

# Package and deploy Lambda code
zip -j lambda.zip lambda/*.py
aws lambda update-function-code \
  --function-name iam-guardrail-enforcer-prod \
  --zip-file fileb://lambda.zip
```

### Subsequent Deployments
Push to `main` — GitHub Actions handles everything automatically.

---

## Running Tests Locally

```bash
# Install dependencies
pip install pytest moto boto3 cfn-lint

# Lint CloudFormation templates
cfn-lint cloudformation/core-stack.yml
cfn-lint cloudformation/app-stack.yml

# Run unit tests
PYTHONPATH=lambda pytest tests/ -v
```

---

## Security Design Decisions

- **Defense in depth** — SCPs act as the outer wall (account level), permission boundaries act as the inner wall (role level). Neither replaces the other.
- **Least privilege Lambda role** — the enforcement Lambda itself has a permission boundary attached, preventing it from being used for privilege escalation.
- **Audit table retention** — DynamoDB table has `DeletionPolicy: Retain` so audit records survive even accidental stack deletion.
- **Secrets in SSM** — Teams webhook URL never touches source code or environment variables directly.
- **Self-healing** — if a boundary is manually removed, the next `AttachRolePolicy` event re-triggers enforcement automatically.
