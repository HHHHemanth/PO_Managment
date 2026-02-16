from pydantic import BaseModel
from typing import Optional

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