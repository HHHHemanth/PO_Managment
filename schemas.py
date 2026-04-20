from pydantic import BaseModel,  Field
from typing import Optional
from pydantic import BaseModel, field_validator
from typing import Optional, List
from pydantic import EmailStr
from datetime import datetime
from enum import Enum

class LoginAdmin(BaseModel):
    password: str


class LoginStaff(BaseModel):
    staff_id: str
    password: str


class RecordCreate(BaseModel):
    indenter_name: str
    staff_id: str
    item_material: str
    project_head: str
    description: str
    pr_po_no: str

    approval_rs: float
    utilization_rs: float

    document1_link: Optional[str] = ""
    document2_link: Optional[str] = ""

    purpose: Optional[str] = ""
    created_at: Optional[datetime] = None

    @field_validator("created_at", mode="before")
    def parse_date(cls, value):
        if value in (None, "", "N/A"):
            return None

        if isinstance(value, datetime):
            return value

        try:
            return datetime.strptime(value, "%d/%m/%Y")
        except ValueError:
            raise ValueError("created_at must be in DD/MM/YYYY format or N/A")

class StaffCreate(BaseModel):
    staff_id: str
    name: str
    password: str
    email: Optional[EmailStr] = None

class WorkCreate(BaseModel):
    staff_id: str
    project_name: str
    objective: str
    task: str
    description: str
    allocated_time: datetime
    deadline_time: datetime



class WorkProgressUpdate(BaseModel):
    progress_description: str = Field(..., min_length=1)



class WorkDelayUpdate(BaseModel):
    reason: str = Field(..., min_length=1)

class WorkSuggestionUpdate(BaseModel):
    suggestion: str = Field(..., min_length=1)

class WorkDocumentResponse(BaseModel):
    document_id: str
    work_id: str
    public_url: str
    status: str
    uploaded_by: str
    uploaded_at: datetime

class WorkUpdate(BaseModel):
    project_name: Optional[str] = None
    objective: Optional[str] = None
    task: Optional[str] = None
    description: Optional[str] = None
    allocated_time: Optional[datetime] = None
    deadline_time: Optional[datetime] = None

class ProjectAssociateUpdate(BaseModel):
    is_active: Optional[bool] = None
    assigned_staff: Optional[List[str]] = None

class LoginProjectAssociate(BaseModel):
    staff_id: str
    password: str

class PasswordChangeRequest(BaseModel):
    staff_id: str
    new_password: str = Field(..., min_length=4)

class WorkProgressValueUpdate(BaseModel):
    progress: int = Field(..., ge=0, le=100)

class WorkTrackerUpdate(BaseModel):
    tracker: str

class PRStatus(str, Enum):
    open = "open"
    closed = "closed"

class PRStatusUpdate(BaseModel):
    pr_status: PRStatus

class FVCUpdate(BaseModel):
    closure_date: Optional[datetime] = None