from enum import Enum

class PolicyClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOW_RISK_VALIDATE = "LOW_RISK_VALIDATE"
    STATE_CHANGE = "STATE_CHANGE"
    DESTRUCTIVE = "DESTRUCTIVE"

AUTO_ALLOWED = {PolicyClass.READ_ONLY, PolicyClass.LOW_RISK_VALIDATE}

ACTION_POLICY = {
    "browser_event_evidence": PolicyClass.READ_ONLY,
    "browser_observe": PolicyClass.READ_ONLY,
    "authorization_test": PolicyClass.READ_ONLY,
    "response_diff": PolicyClass.READ_ONLY,
    "request_import": PolicyClass.READ_ONLY,
    "request_replay": PolicyClass.READ_ONLY,
    "agent_plan": PolicyClass.READ_ONLY,
    "js_analyze": PolicyClass.READ_ONLY,
    "web_discovery": PolicyClass.READ_ONLY,
    "project_scan": PolicyClass.LOW_RISK_VALIDATE,
    "http_probe": PolicyClass.READ_ONLY,
    "headers_check": PolicyClass.READ_ONLY,
    "tls_check": PolicyClass.READ_ONLY,
    "port_scan": PolicyClass.LOW_RISK_VALIDATE,
    "ai_analyze": PolicyClass.READ_ONLY,

    # Explicitly denied in V0.1:
    "credential_bruteforce": PolicyClass.DESTRUCTIVE,
    "password_spray": PolicyClass.DESTRUCTIVE,
    "arbitrary_command": PolicyClass.DESTRUCTIVE,
    "upload_file": PolicyClass.STATE_CHANGE,
    "delete_data": PolicyClass.DESTRUCTIVE,
    "modify_remote_data": PolicyClass.STATE_CHANGE,
    "dos_test": PolicyClass.DESTRUCTIVE,
}

def classify_action(action: str) -> PolicyClass:
    return ACTION_POLICY.get(action, PolicyClass.DESTRUCTIVE)

def is_auto_allowed(action: str) -> bool:
    return classify_action(action) in AUTO_ALLOWED
