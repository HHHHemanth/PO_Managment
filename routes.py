from fastapi import APIRouter, HTTPException, Depends
from database import users_collection, records_collection
from schemas import LoginAdmin, LoginStaff, RecordCreate, StaffCreate
from auth import verify_password, create_token
from audit import log_action

from bson import ObjectId
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os

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


# ---------------- DELETE RECORD ---------------- #

@router.delete("/records/{record_id}")
async def delete_record(record_id: str, user=Depends(get_current_user)):

    record = await records_collection.find_one(
        {"_id": ObjectId(record_id)}
    )

    if not record:
        raise HTTPException(404, "Record not found")

    if user["role"] != "admin" and record["staff_id"] != user["staff_id"]:
        raise HTTPException(403, "Not authorized")

    await records_collection.delete_one(
        {"_id": ObjectId(record_id)}
    )

    await log_action(
        action="DELETE",
        performed_by=user["staff_id"],
        record_id=record_id,
        details=f"Deleted PR/PO {record.get('pr_po_no', '')}"
    )

    return {"message": "Record deleted"}

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
