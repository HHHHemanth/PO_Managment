from fastapi import APIRouter, HTTPException, Depends
from database import users_collection, records_collection, records_deleted_collection, users_deleted_collection
from schemas import LoginAdmin, LoginStaff, RecordCreate, StaffCreate
from auth import verify_password, create_token
from audit import log_action

from bson import ObjectId
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os

from datetime import datetime

router = APIRouter()

# JWT Security setup
security = HTTPBearer()

SECRET = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM")


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

# ---------------- AUTH ---------------- #
# ---------------- LOGIN ROUTES ---------------- #

@router.post("/login/admin")
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


@router.post("/login/staff")
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

# ---------------- END AUTH ---------------- #

# ---------------- RECORDS (ACTIVE) ---------------- #
# ---------------- CREATE RECORD ---------------- #

@router.post("/records")
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

@router.get("/records")
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
@router.put("/records/{record_id}")
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

@router.delete("/records/{record_id}")
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
            raise HTTPException(403, "You can delete only your own records")

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

@router.get("/records/deleted")
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

@router.get("/admin/deleted/records")
async def view_deleted_records(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view deleted records")

    records = await records_deleted_collection.find().to_list(1000)

    for record in records:
        record["_id"] = str(record["_id"])
        record["original_id"] = str(record.get("original_id", ""))

    return records


# ---------------- RESTORE RECORD (ADMIN + STAFF OWN RECORDS) ---------------- #

@router.post("/records/restore/{record_id}")
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

@router.get("/admin/staffs")
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

@router.post("/admin/create-staff")
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

@router.delete("/staff/{staff_id}")
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

@router.get("/admin/deleted/staffs")
async def view_deleted_staff(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view deleted staff")

    staffs = await users_deleted_collection.find().to_list(1000)

    for staff in staffs:
        staff["_id"] = str(staff["_id"])
        staff.pop("password_hash", None)

    return staffs

# ---------------- RESTORE STAFF---------------- #
@router.post("/staff/restore/{staff_id}")
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


# ---------------- END STAFF (DELETED / RESTORE) ---------------- #