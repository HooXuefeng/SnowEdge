from pydantic import BaseModel, Field

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scope: list[str] = Field(min_length=1)

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=1000)
