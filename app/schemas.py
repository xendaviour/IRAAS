from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime

# User schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def password_complexity(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

class Token(BaseModel):
    access_token: str
    token_type: str

# Incident schemas
class IncidentBase(BaseModel):
    title: str = Field(..., min_length=5, max_length=120)
    description: Optional[str] = None
    severity: str = Field('Medium', pattern=r'^(Low|Medium|High|Critical)$')
    incident_type: str

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=5, max_length=120)
    description: Optional[str] = None
    severity: Optional[str] = Field(None, pattern=r'^(Low|Medium|High|Critical)$')
    status: Optional[str] = Field(None, pattern=r'^(New|Investigating|Resolved|Closed)$')
    incident_type: Optional[str] = None

class IncidentResponseBase(BaseModel):
    step_number: int
    action: str
    notes: Optional[str] = None
    completed: bool = False

class IncidentResponseCreate(IncidentResponseBase):
    pass

class IncidentResponseUpdate(BaseModel):
    action: Optional[str] = None
    notes: Optional[str] = None
    completed: Optional[bool] = None

class IncidentResponse(IncidentResponseBase):
    id: int
    completed_at: Optional[datetime] = None
    created_at: datetime
    incident_id: int
    
    class Config:
        orm_mode = True

class Incident(IncidentBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime
    user_id: int
    responses: List[IncidentResponse] = []
    
    class Config:
        orm_mode = True

# Template schemas
class TemplateStepBase(BaseModel):
    step_number: int
    action: str
    description: Optional[str] = None

class TemplateStepCreate(TemplateStepBase):
    pass

class TemplateStepUpdate(BaseModel):
    action: Optional[str] = None
    description: Optional[str] = None

class TemplateStep(TemplateStepBase):
    id: int
    template_id: int
    
    class Config:
        orm_mode = True

class IncidentTemplateBase(BaseModel):
    name: str
    description: Optional[str] = None
    incident_type: str

class IncidentTemplateCreate(IncidentTemplateBase):
    steps: List[TemplateStepCreate]

class IncidentTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    incident_type: Optional[str] = None

class IncidentTemplate(IncidentTemplateBase):
    id: int
    created_at: datetime
    steps: List[TemplateStep] = []
    
    class Config:
        orm_mode = True

# CLI specific schemas
class CLIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
