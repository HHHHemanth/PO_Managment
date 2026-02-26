from fastapi import APIRouter, HTTPException, Depends
from database import users_collection, records_collection, records_deleted_collection, users_deleted_collection, document_links_collection, work_collection, work_document_collection
from schemas import LoginAdmin, LoginStaff, RecordCreate, StaffCreate, WorkCreate, WorkProgressUpdate, WorkDelayUpdate, WorkUpdate, ProjectAssociateUpdate, LoginProjectAssociate
from auth import verify_password, create_token
from audit import log_action

from bson import ObjectId
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import uuid

from datetime import datetime, timezone
from fastapi import UploadFile, File, Form
import uuid
from supabase_client import supabase

import re

router = APIRouter()

# JWT Security setup
security = HTTPBearer()

SECRET = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM")

def sanitize_folder_name(pr_po_no: str):
    # Replace all unsafe characters with underscore
    return re.sub(r"[^a-zA-Z0-9_-]", "_", pr_po_no)

async def can_staff_access_work(user, work):

    # Admin always allowed
    if user["role"] == "admin":
        return True

    # Project associate (owner of work)
    if user["role"] == "project_associate":
        return work["staff_id"] == user["staff_id"]

    # Staff supervising associate
    if user["role"] == "staff":

        associate = await users_collection.find_one({
            "staff_id": work["staff_id"],
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        })

        return associate is not None

    return False


# ✅ DEFINE THIS FIRST (before routes use it)
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):

    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


def calculate_status(allocated, deadline):
    now = datetime.utcnow()
    total = (deadline - allocated).total_seconds()
    elapsed = (now - allocated).total_seconds()

    if total <= 0:
        return "red"

    ratio = elapsed / total

    if ratio <= 1/3:
        return "green"
    elif ratio <= 2/3:
        return "yellow"
    else:
        return "red"







# ---------------- AUTH ---------------- #
# ---------------- LOGIN ROUTES ---------------- #

@router.post("/login/admin", tags=["Authentication"])
async def admin_login(data: LoginAdmin):

    admin = await users_collection.find_one({"role": "admin"})

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    if not verify_password(data.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    token = create_token({
        "role": "admin",
        "staff_id": admin["staff_id"]
    })

    return {"token": token}


@router.post("/login/staff", tags=["Authentication"])
async def staff_login(data: LoginStaff):

    staff = await users_collection.find_one({"staff_id": data.staff_id})

    if not staff:
        raise HTTPException(status_code=404, detail="Staff not found")

    if not verify_password(data.password, staff["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    token = create_token({
        "role": "staff",
        "staff_id": data.staff_id
    })

    return {"token": token, "staff_id": data.staff_id, "name": staff["name"], "role": staff["role"]}



@router.post("/login/project-associate", tags=["Authentication"])
async def project_associate_login(data: LoginProjectAssociate):

    associate = await users_collection.find_one({
        "staff_id": data.staff_id,
        "role": "project_associate",
        "is_active": True
    })

    if not associate:
        raise HTTPException(status_code=404, detail="Project associate not found")

    if not verify_password(data.password, associate["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    token = create_token({
        "role": "project_associate",
        "staff_id": associate["staff_id"]
    })

    return {
        "token": token,
        "staff_id": associate["staff_id"],
        "name": associate["name"],
        "role": associate["role"]
    }

# ---------------- END AUTH ---------------- #

# ---------------- RECORDS (ACTIVE) ---------------- #
# ---------------- CREATE RECORD ---------------- #

@router.post("/records", tags=["Records"])
async def create_record(record: RecordCreate, user=Depends(get_current_user)):

    approval = record.approval_rs
    utilization = record.utilization_rs
    remaining = approval - utilization

    new_record = record.dict()
    new_record["total"] = approval
    new_record["remaining"] = remaining

    result = await records_collection.insert_one(new_record)

    # Audit log
    await log_action(
        action="CREATE",
        performed_by=user["staff_id"],
        record_id=str(result.inserted_id),
        details=f"Created PR/PO {record.pr_po_no}"
    )

    return {
        "message": "Record created",
        "record_id": str(result.inserted_id),
        "remaining": remaining
    }


# ---------------- GET RECORDS ---------------- #

@router.get("/records", tags=["Records"])
async def get_records(user=Depends(get_current_user)):

    if user["role"] == "admin":
        records = await records_collection.find().to_list(1000)
    else:
        records = await records_collection.find(
            {"staff_id": user["staff_id"]}
        ).to_list(1000)

    for record in records:
        record["_id"] = str(record["_id"])

    return records


# ---------------- UPDATE RECORD ---------------- #
@router.put("/records/{record_id}", tags=["Records"])
async def update_record(record_id: str, record: RecordCreate, user=Depends(get_current_user)):

    approval = record.approval_rs
    utilization = record.utilization_rs
    remaining = approval - utilization

    update_data = record.dict()
    update_data["remaining"] = remaining

    await records_collection.update_one(
        {"_id": ObjectId(record_id)},
        {"$set": update_data}
    )

    await log_action(
        action="UPDATE",
        performed_by=user["staff_id"],
        record_id=record_id,
        details=f"Updated PR/PO {record.pr_po_no}"
    )

    return {"message": "Record updated"}



# ---------------- DELETE RECORD (ADMIN + STAFF OWN RECORDS) ---------------- #

@router.delete("/records/{record_id}", tags=["Records"])
async def delete_record(record_id: str, user=Depends(get_current_user)):

    record = await records_collection.find_one({"_id": ObjectId(record_id)})

    if not record:
        raise HTTPException(404, "Record not found")

    # Admin can delete any record
    if user["role"] == "admin":
        pass

    # Staff can delete only their own records
    elif user["role"] == "staff":
        if record["staff_id"] != user["staff_id"]:
            raise HTTPException(
                403,
                "You can delete only your own records"
            )

    else:
        raise HTTPException(403, "Not authorized")

    # Add deletion metadata
    record["deleted_at"] = datetime.utcnow()
    record["deleted_by"] = user["staff_id"]
    record["original_id"] = record["_id"]

    # Move to deleted collection
    await records_deleted_collection.insert_one(record)

    # Remove from main collection
    await records_collection.delete_one({"_id": ObjectId(record_id)})

    await log_action(
        action="DELETE",
        performed_by=user["staff_id"],
        record_id=record_id,
        details="Soft deleted record"
    )

    return {"message": "Record moved to deleted collection"}


# ---------------- END RECORDS (ACTIVE) ---------------- #

# ---------------- RECORDS (DELETED / RESTORE) ---------------- #

# ---------------- VIEW MY DELETED RECORDS ---------------- #

@router.get("/records/deleted", tags=["Records - Deleted"])
async def view_my_deleted_records(user=Depends(get_current_user)):

    if user["role"] == "admin":
        # Admin sees all
        records = await records_deleted_collection.find().to_list(1000)
    else:
        # Staff sees only their deleted records
        records = await records_deleted_collection.find(
            {"staff_id": user["staff_id"]}
        ).to_list(1000)

    for record in records:
        record["_id"] = str(record["_id"])
        record["original_id"] = str(record.get("original_id", ""))

    return records





# ---------------- VIEW DELETED RECORDS (ADMIN ONLY) ---------------- #

@router.get("/admin/deleted/records", tags=["Records - Deleted"])
async def view_deleted_records(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view deleted records")

    records = await records_deleted_collection.find().to_list(1000)

    for record in records:
        record["_id"] = str(record["_id"])
        record["original_id"] = str(record.get("original_id", ""))

    return records


# ---------------- RESTORE RECORD (ADMIN + STAFF OWN RECORDS) ---------------- #

@router.post("/records/restore/{record_id}", tags=["Records - Deleted"])
async def restore_record(record_id: str, user=Depends(get_current_user)):

    deleted_record = await records_deleted_collection.find_one(
        {"original_id": ObjectId(record_id)}
    )

    if not deleted_record:
        raise HTTPException(404, "Deleted record not found")

    # Admin can restore any record
    if user["role"] == "admin":
        pass

    # Staff can restore only their own records
    elif user["role"] == "staff":
        if deleted_record["staff_id"] != user["staff_id"]:
            raise HTTPException(403, "You can restore only your own records")

    else:
        raise HTTPException(403, "Not authorized")

    # Remove deletion metadata
    deleted_record.pop("deleted_at", None)
    deleted_record.pop("deleted_by", None)
    deleted_record.pop("original_id", None)

    # Restore to main collection
    await records_collection.insert_one(deleted_record)

    # Remove from deleted collection
    await records_deleted_collection.delete_one(
        {"original_id": ObjectId(record_id)}
    )

    await log_action(
        action="RESTORE",
        performed_by=user["staff_id"],
        record_id=record_id,
        details="Record restored"
    )

    return {"message": "Record restored successfully"}


# ---------------- END RECORDS (DELETED / RESTORE) ---------------- #



# ---------------- STAFF (ACTIVE) ---------------- #
# ---------------- VIEW ALL STAFF (ADMIN ONLY) ---------------- #

@router.get("/admin/staffs", tags=["Staff Management"])
async def get_all_staff(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view staff list")

    staffs = await users_collection.find(
        {"role": "staff"}  # Only staff, exclude admin
    ).to_list(1000)

    # Remove sensitive fields
    for staff in staffs:
        staff["_id"] = str(staff["_id"])
        staff.pop("password_hash", None)

    return staffs

# ---------------- CREATE STAFF---------------- #

@router.post("/admin/create-staff", tags=["Staff Management"])
async def create_staff(data: StaffCreate, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create staff")

    from auth import hash_password

    hashed = hash_password(data.password)

    new_staff = {
        "staff_id": data.staff_id,
        "name": data.name,
        "password_hash": hashed,
        "role": "staff",
        "is_active": True
    }

    await users_collection.insert_one(new_staff)

    return {"message": "Staff created successfully"}


# ---------------- DELETE STAFF---------------- #

@router.delete("/staff/{staff_id}", tags=["Staff Management"])
async def delete_staff(staff_id: str, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can delete staff")

    staff = await users_collection.find_one({"staff_id": staff_id})

    if not staff:
        raise HTTPException(404, "Staff not found")

    from datetime import datetime

    staff["deleted_at"] = datetime.utcnow()
    staff["deleted_by"] = user["staff_id"]

    await users_deleted_collection.insert_one(staff)
    await users_collection.delete_one({"staff_id": staff_id})

    return {"message": "Staff moved to deleted collection"}


# ---------------- END STAFF (ACTIVE) ---------------- #


# ---------------- STAFF (DELETED / RESTORE) ---------------- #

# ---------------- VIEW DELETED STAFF (ADMIN ONLY) ---------------- #

@router.get("/admin/deleted/staffs", tags=["Staff Management"])
async def view_deleted_staff(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view deleted staff")

    staffs = await users_deleted_collection.find().to_list(1000)

    for staff in staffs:
        staff["_id"] = str(staff["_id"])
        staff.pop("password_hash", None)

    return staffs

# ---------------- RESTORE STAFF---------------- #
@router.post("/staff/restore/{staff_id}", tags=["Staff Management"])
async def restore_staff(staff_id: str, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can restore staff")

    staff = await users_deleted_collection.find_one({"staff_id": staff_id})

    if not staff:
        raise HTTPException(404, "Deleted staff not found")

    staff.pop("deleted_at", None)
    staff.pop("deleted_by", None)

    await users_collection.insert_one(staff)
    await users_deleted_collection.delete_one({"staff_id": staff_id})

    return {"message": "Staff restored successfully"}



@router.post("/admin/project-associate", tags=["Project Associate Management"])
async def create_project_associate(data: StaffCreate, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can create project associate")

    from auth import hash_password

    existing = await users_collection.find_one({"staff_id": data.staff_id})
    if existing:
        raise HTTPException(400, "Staff ID already exists")

    new_associate = {
        "staff_id": data.staff_id,
        "name": data.name,
        "password_hash": hash_password(data.password),
        "role": "project_associate",
        "is_active": True,
        "assigned_staff": [],
        "created_at": datetime.utcnow()
    }

    await users_collection.insert_one(new_associate)

    return {"message": "Project Associate created successfully"}





@router.put("/admin/project-associate/{staff_id}", tags=["Project Associate Management"])
async def update_project_associate(
    staff_id: str,
    data: ProjectAssociateUpdate,
    user=Depends(get_current_user)
):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can update")

    associate = await users_collection.find_one({
        "staff_id": staff_id,
        "role": "project_associate"
    })

    if not associate:
        raise HTTPException(404, "Project associate not found")

    update_data = data.dict(exclude_unset=True)

    await users_collection.update_one(
        {"staff_id": staff_id},
        {"$set": update_data}
    )

    return {"message": "Project associate updated successfully"}




@router.delete("/admin/project-associate/{staff_id}", tags=["Project Associate Management"])
async def delete_project_associate(staff_id: str, user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can delete")

    associate = await users_collection.find_one({
        "staff_id": staff_id,
        "role": "project_associate"
    })

    if not associate:
        raise HTTPException(404, "Project associate not found")
    associate["is_active"] = False
    associate["deleted_at"] = datetime.utcnow()
    associate["deleted_by"] = user["staff_id"]

    await users_deleted_collection.insert_one(associate)
    await users_collection.delete_one({"staff_id": staff_id})

    return {"message": "Project associate soft deleted"}





@router.post("/admin/project-associate/restore/{staff_id}", tags=["Project Associate Management"])
async def restore_project_associate(staff_id: str, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can restore")
    associate = await users_deleted_collection.find_one({
        "staff_id": staff_id,
        "role": "project_associate"
    })

    if not associate:
        raise HTTPException(404, "Deleted associate not found")
    associate["is_active"] = True
    associate.pop("deleted_at", None)
    associate.pop("deleted_by", None)

    await users_collection.insert_one(associate)
    await users_deleted_collection.delete_one({"staff_id": staff_id})

    return {"message": "Project associate restored successfully"}




@router.get("/admin/project-associates", tags=["Project Associate Management"])
async def get_project_associates(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can view")

    associates = await users_collection.find({
        "role": "project_associate"
    }).to_list(1000)

    for a in associates:
        a["_id"] = str(a["_id"])
        a.pop("password_hash", None)

    return associates


@router.get("/admin/staff/{staff_id}/associates", tags=["Project Associate Management"])
async def get_associates_under_staff(staff_id: str, user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(403, "Only admin allowed")

    staff = await users_collection.find_one({
        "staff_id": staff_id,
        "role": "staff"
    })

    if not staff:
        raise HTTPException(404, "Staff not found")

    associates = await users_collection.find({
        "role": "project_associate",
        "assigned_staff": staff_id,
        "is_active": True
    }).to_list(1000)

    for a in associates:
        a["_id"] = str(a["_id"])
        a.pop("password_hash", None)

    return {
        "staff_id": staff_id,
        "associates": associates
    }


@router.get("/staff/my-associates", tags=["Project Associate Management"])
async def staff_view_associates(user=Depends(get_current_user)):

    if user["role"] != "staff":
        raise HTTPException(403, "Only staff allowed")

    associates = await users_collection.find({
        "role": "project_associate",
        "assigned_staff": user["staff_id"],
        "is_active": True
    }).to_list(1000)

    for a in associates:
        a["_id"] = str(a["_id"])
        a.pop("password_hash", None)

    return associates


# ---------------- END STAFF (DELETED / RESTORE) ---------------- #


# ---------------- DOCUMENT PART  ---------------- #


# ---------------- UPLOAD DOCUMENT ---------------- #


@router.post("/records/{record_id}/upload", tags=["Documents"])
async def upload_document(
    record_id: str,
    document_name: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):

    # Validate record exists
    record = await records_collection.find_one({"_id": ObjectId(record_id)})
    if not record:
        raise HTTPException(404, "Record not found")

    # Staff restriction
    if user["role"] == "staff" and record["staff_id"] != user["staff_id"]:
        raise HTTPException(403, "Not authorized")

    safe_pr_po_no = sanitize_folder_name(record["pr_po_no"])

    # Validate file type
    allowed_types = ["application/pdf", "image/jpeg", "image/png"]
    if file.content_type not in allowed_types:
        raise HTTPException(400, "Only PDF/JPEG/PNG allowed")

    #  CHECK FOR DUPLICATE NAME
    existing = await document_links_collection.find_one({
        "record_id": ObjectId(record_id),
        "document_name": document_name,
        "status": "active"
    })

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Document name already exists for this record"
        )

    # Generate document_id
    document_id = str(uuid.uuid4())

    file_extension = file.filename.split(".")[-1]
    file_name = f"{document_name}.{file_extension}"

    file_path = f"{safe_pr_po_no}/{file_name}"

    # Upload to Supabase
    file_bytes = await file.read()

    supabase.storage.from_("PO_Managment_Documents").upload(
        file_path,
        file_bytes,
        {
            "content-type": file.content_type
        }
    )

    public_url = supabase.storage.from_("PO_Managment_Documents").get_public_url(file_path)

    # Save in MongoDB
    document_data = {
        "document_id": document_id,
        "record_id": ObjectId(record_id),
        "pr_po_no": safe_pr_po_no,
        "document_name": document_name,
        "file_extension": file_extension,
        "file_path": file_path,
        "public_url": public_url,
        "status": "active",
        "uploaded_by": user["staff_id"],
        "uploaded_at": datetime.utcnow(),
        "deleted_by": None,
        "deleted_at": None
    }

    await document_links_collection.insert_one(document_data)

    return {
        "message": "Document uploaded successfully",
        "document_id": document_id,
        "record_id": record_id,
        "name": document_name,
        "url": public_url
    }

# ---------------- VIEW DOCUMENT ---------------- #

@router.get("/records/{record_id}/documents/{document_id}", tags=["Documents"])
async def view_document(record_id: str, document_id: str, user=Depends(get_current_user)):

    document = await document_links_collection.find_one({
        "document_id": document_id,
        "record_id": ObjectId(record_id),
        "status": "active"
    })

    if not document:
        raise HTTPException(404, "Document not found")

    # Staff restriction
    record = await records_collection.find_one({"_id": ObjectId(record_id)})
    if user["role"] == "staff" and record["staff_id"] != user["staff_id"]:
        raise HTTPException(403, "Not authorized")

    return {
        "document_id": document_id,
        "url": document["public_url"]
    }



# ---------------- DELETE DOCUMENT (SOFT) ---------------- #

@router.delete("/documents/{document_id}", tags=["Documents"])
async def delete_document(document_id: str, user=Depends(get_current_user)):

    document = await document_links_collection.find_one({
        "document_id": document_id,
        "status": "active"
    })

    if not document:
        raise HTTPException(404, "Document not found")

    await document_links_collection.update_one(
        {"document_id": document_id},
        {
            "$set": {
                "status": "deleted",
                "deleted_by": user["staff_id"],
                "deleted_at": datetime.utcnow()
            }
        }
    )

    return {"message": "Document marked as deleted"}



@router.get("/records/{record_id}/documents", tags=["Documents"])
async def list_documents(record_id: str, user=Depends(get_current_user)):

    documents = await document_links_collection.find({
        "record_id": ObjectId(record_id),
        "status": "active"
    }).to_list(100)

    for doc in documents:
        doc["_id"] = str(doc["_id"])
        doc["record_id"] = str(doc["record_id"])

    return documents



@router.get("/works", tags=["Taskbar"])
async def get_works(user=Depends(get_current_user)):

    if user["role"] == "admin":
        works = await work_collection.find().to_list(1000)

    elif user["role"] == "staff":

        associates = await users_collection.find({
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        }).to_list(1000)

        associate_ids = [a["staff_id"] for a in associates]

        works = await work_collection.find({
            "staff_id": {"$in": associate_ids},
            "is_deleted": {"$ne": True}
        }).to_list(1000)

    elif user["role"] == "project_associate":
        works = await work_collection.find({
            "staff_id": user["staff_id"],
            "is_deleted": {"$ne": True}
        }).to_list(1000)
    else:
        raise HTTPException(403, "Unauthorized")

    for work in works:
        work["_id"] = str(work["_id"])

        # Auto compute status
        work["status"] = calculate_status(
            work["allocated_time"],
            work["deadline_time"]
        )

    return works



@router.post("/works", tags=["Taskbar"])
async def create_work(data: WorkCreate, user=Depends(get_current_user)):

    if user["role"] not in ["admin", "staff"]:
        raise HTTPException(403, "Only admin or staff can create work")

    # 1️⃣ Validate associate exists & active
    associate = await users_collection.find_one({
        "staff_id": data.staff_id,
        "role": "project_associate",
        "is_active": True
    })

    if not associate:
        raise HTTPException(404, "Project associate not found or inactive")

    # 2️⃣ If staff, ensure associate is assigned under them
    if user["role"] == "staff":

        if user["staff_id"] not in associate.get("assigned_staff", []):
            raise HTTPException(
                403,
                "You can assign work only to associates allocated to you"
            )

    # 3️⃣ Create Work
    work_id = str(uuid.uuid4())

    work_data = {
        "work_id": work_id,
        "is_deleted": False,

        "staff_id": data.staff_id,
        "associate_name": associate["name"],

        "project_name": data.project_name,
        "objective": data.objective,
        "task": data.task,
        "description": data.description,

        "allocated_time": data.allocated_time,
        "deadline_time": data.deadline_time,

        "progress_description": "",
        "reason_for_delay": None,

        "created_by": user["staff_id"],
        "created_role": user["role"],
        "created_at": datetime.utcnow()
    }

    await work_collection.insert_one(work_data)

    return {
        "message": "Work created successfully",
        "work_id": work_id
    }





@router.put("/works/{work_id}", tags=["Taskbar"])
async def update_work(
    work_id: str,
    data: WorkUpdate,
    user=Depends(get_current_user)
):

    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    # Admin can edit anything
    if user["role"] == "admin":
        pass

    # Staff can edit only works they created
    elif user["role"] == "staff":

        associate = await users_collection.find_one({
            "staff_id": work["staff_id"],
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        })

        if not associate:
            raise HTTPException(403, "You can update only works of your associates")

    # Project associate can edit only their work
    elif user["role"] == "project_associate":
        if work["staff_id"] != user["staff_id"]:
            raise HTTPException(403, "Not your work")

    else:
        raise HTTPException(403, "Unauthorized")

    update_data = data.dict(exclude_unset=True)

    if not update_data:
        raise HTTPException(400, "No fields provided for update")

    await work_collection.update_one(
        {"work_id": work_id},
        {"$set": update_data}
    )

    return {"message": "Work updated successfully"}


@router.put("/works/{work_id}/progress", tags=["Taskbar"])
async def update_progress(
    work_id: str,
    data: WorkProgressUpdate,
    user=Depends(get_current_user)
):

    if user["role"] != "project_associate":
        raise HTTPException(403, "Only associate can update progress")

    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    if work["staff_id"] != user["staff_id"]:
        raise HTTPException(403, "Not your work")

    await work_collection.update_one(
        {"work_id": work_id},
        {"$set": {"progress_description": data.progress_description}}
    )

    return {"message": "Progress updated"}


@router.put("/works/{work_id}/delay", tags=["Taskbar"])
async def add_delay_reason(
    work_id: str,
    data: WorkDelayUpdate,
    user=Depends(get_current_user)
):

    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    if user["role"] != "project_associate":
        raise HTTPException(403, "Only associate can add delay reason")

    if work["staff_id"] != user["staff_id"]:
        raise HTTPException(403, "Not your work")

    if datetime.now(timezone.utc) < work["deadline_time"]:
        raise HTTPException(400, "Deadline not reached yet")

    await work_collection.update_one(
        {"work_id": work_id},
        {"$set": {"reason_for_delay": data.reason}}
    )

    return {"message": "Delay reason added"}



@router.post("/works/{work_id}/upload", tags=["Taskbar"])
async def upload_work_document(
    work_id: str,
    document_name: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):

    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    # ---------------- PERMISSION LOGIC ---------------- #

    if not await can_staff_access_work(user, work):
        raise HTTPException(403, "Not authorized to upload for this work")

    # ---------------- FILE VALIDATION ---------------- #

    allowed_types = ["pdf", "png", "jpg", "jpeg"]
    file_extension = file.filename.split(".")[-1].lower()

    if file_extension not in allowed_types:
        raise HTTPException(400, "Only PDF/JPEG/PNG allowed")

    # ---------------- DUPLICATE NAME CHECK ---------------- #

    existing = await work_document_collection.find_one({
        "work_id": work_id,
        "file_path": {"$regex": f"/{document_name}\\."},
        "status": "active"
    })

    if existing:
        raise HTTPException(400, "Document name already exists")

    # ---------------- UPLOAD ---------------- #


    staff_id = work["staff_id"]

    file_path = f"works/{staff_id}/{work_id}/{document_name}.{file_extension}"
    file_bytes = await file.read()

    supabase.storage.from_("PO_Managment_Documents").upload(
        file_path,
        file_bytes
    )

    public_url = supabase.storage.from_("PO_Managment_Documents").get_public_url(file_path)

    document_id = str(uuid.uuid4())

    await work_document_collection.insert_one({
        "document_id": document_id,
        "work_id": work_id,
        "file_path": file_path,
        "public_url": public_url,
        "status": "active",
        "uploaded_by": user["staff_id"],
        "uploaded_at": datetime.utcnow()
    })

    return {"message": "Document uploaded", "document_id": document_id}

@router.get("/works/{work_id}/documents", tags=["Taskbar"])
async def list_work_documents(work_id: str, user=Depends(get_current_user)):

    # 1️⃣ Check work exists
    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    # 2️⃣ Permission Logic

    if not await can_staff_access_work(user, work):
        raise HTTPException(403, "Not authorized to view documents")

    # 3️⃣ Fetch documents
    documents = await work_document_collection.find({
        "work_id": work_id,
        "status": "active"
    }).to_list(100)

    for doc in documents:
        doc["_id"] = str(doc["_id"])

    return documents


@router.delete("/work-documents/{document_id}", tags=["Taskbar"])
async def delete_work_document(document_id: str, user=Depends(get_current_user)):

    document = await work_document_collection.find_one({
        "document_id": document_id,
        "status": "active"
    })

    if not document:
        raise HTTPException(404, "Document not found")

    work = await work_collection.find_one({
        "work_id": document["work_id"]
    })

    if not work:
        raise HTTPException(404, "Work not found")

    # Admin always allowed
    if user["role"] == "admin":
        pass

    # Project associate owner
    elif user["role"] == "project_associate":
        if work["staff_id"] != user["staff_id"]:
            raise HTTPException(403, "Not your work")

    # Assigned staff
    elif user["role"] == "staff":

        associate = await users_collection.find_one({
            "staff_id": work["staff_id"],
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        })

        if not associate:
            raise HTTPException(403, "Not authorized")

    else:
        raise HTTPException(403, "Unauthorized")

    # Soft delete
    await work_document_collection.update_one(
        {"document_id": document_id},
        {
            "$set": {
                "status": "deleted",
                "deleted_by": user["staff_id"],
                "deleted_at": datetime.utcnow()
            }
        }
    )

    return {"message": "Document deleted successfully"}



@router.get("/staff/my-works", tags=["Taskbar"])
async def staff_view_works(user=Depends(get_current_user)):

    if user["role"] != "staff":
        raise HTTPException(403, "Only staff allowed")

    # get associate ids under staff
    associates = await users_collection.find({
        "role": "project_associate",
        "assigned_staff": user["staff_id"],
        "is_active": True
    }).to_list(1000)

    associate_ids = [a["staff_id"] for a in associates]

    works = await work_collection.find({
        "staff_id": {"$in": associate_ids},
        "is_deleted": {"$ne": True}
    }).to_list(1000)

    for work in works:
        work["_id"] = str(work["_id"])
        work["status"] = calculate_status(
            work["allocated_time"],
            work["deadline_time"]
        )

    return works



@router.delete("/works/{work_id}", tags=["Taskbar"])
async def soft_delete_work(work_id: str, user=Depends(get_current_user)):

    work = await work_collection.find_one({"work_id": work_id})

    if not work:
        raise HTTPException(404, "Work not found")

    # Admin → always allowed
    if user["role"] == "admin":
        pass

    # Staff → only if associate belongs to them
    elif user["role"] == "staff":

        associate = await users_collection.find_one({
            "staff_id": work["staff_id"],
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        })

        if not associate:
            raise HTTPException(
                403,
                "You can delete only works of your assigned associates"
            )

    else:
        raise HTTPException(403, "Unauthorized")

    await work_collection.update_one(
        {"work_id": work_id},
        {
            "$set": {
                "is_deleted": True,
                "deleted_at": datetime.utcnow(),
                "deleted_by": user["staff_id"]
            }
        }
    )

    return {"message": "Work soft deleted successfully"}



@router.post("/works/restore/{work_id}", tags=["Taskbar"])
async def restore_work(work_id: str, user=Depends(get_current_user)):

    work = await work_collection.find_one({
        "work_id": work_id,
        "is_deleted": True
    })

    if not work:
        raise HTTPException(404, "Deleted work not found")

    # Admin → allowed
    if user["role"] == "admin":
        pass

    # Staff → only if associate belongs to them
    elif user["role"] == "staff":

        associate = await users_collection.find_one({
            "staff_id": work["staff_id"],
            "role": "project_associate",
            "assigned_staff": user["staff_id"],
            "is_active": True
        })

        if not associate:
            raise HTTPException(
                403,
                "You can restore only works of your assigned associates"
            )

    else:
        raise HTTPException(403, "Unauthorized")

    await work_collection.update_one(
        {"work_id": work_id},
        {
            "$set": {
                "is_deleted": False
            },
            "$unset": {
                "deleted_at": "",
                "deleted_by": ""
            }
        }
    )

    return {"message": "Work restored successfully"}


@router.get("/works/deleted", tags=["Taskbar"])
async def view_deleted_works(user=Depends(get_current_user)):

    if user["role"] == "admin":
        works = await work_collection.find({"is_deleted": True}).to_list(1000)

    elif user["role"] == "staff":

        associates = await users_collection.find({
            "role": "project_associate",
            "assigned_staff": user["staff_id"]
        }).to_list(1000)

        associate_ids = [a["staff_id"] for a in associates]

        works = await work_collection.find({
            "staff_id": {"$in": associate_ids},
            "is_deleted": True
        }).to_list(1000)

    else:
        raise HTTPException(403, "Unauthorized")

    for work in works:
        work["_id"] = str(work["_id"])

    return works