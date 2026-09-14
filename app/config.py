from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from .install_secret import installation_secret
from pathlib import Path

def default_database_url():
    # Existing installations must keep their database without copying live SQLite files.
    return 'sqlite:///./ai_pentest.db' if Path('ai_pentest.db').exists() else 'sqlite:///./snowedge.db'

class Settings(BaseSettings):
    app_name: str = "SnowEdge"
    @field_validator('app_name')
    @classmethod
    def normalize_product_name(cls,value):
        normalized=value.lower().replace('_',' ').replace('-',' ')
        return 'SnowEdge' if normalized.startswith('ai pentest') else value
    database_url: str = Field(default_factory=default_database_url)
    ai_provider: str = "mock"
    ai_api_base: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    app_secret_key: str = Field(default_factory=installation_secret)
    local_allowed_hosts: str = '127.0.0.1,localhost,::1'
    ai_include_response_body: bool = False
    request_timeout_seconds: float = 8.0
    max_response_body_bytes: int = 200_000
    max_project_tasks: int = 100
    authorization_auto_candidate_findings: bool = True
    authorization_auto_candidate_min_confidence: int = 85
    browser_headless: bool = True
    browser_navigation_timeout_seconds: float = 12.0
    browser_post_load_wait_ms: int = 1200
    browser_artifact_dir: str = "./browser_artifacts"
    evidence_artifact_dir: str = "./evidence_artifacts"
    restore_pending_dir: str = "./restore_pending"
    job_worker_count: int = 2
    job_poll_interval_seconds: float = 0.5
    job_default_timeout_seconds: int = 300
    job_default_max_attempts: int = 2
    job_lease_seconds: int = 45
    job_heartbeat_seconds: int = 10
    job_embedded_workers: int = 0
    job_immediate_accelerator: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
