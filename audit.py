from database import audit_logs_collection
from datetime import datetime

async def log_action(action, performed_by, record_id=None, details=""):

    log = {
        "action": action,
        "performed_by": performed_by,
        "record_id": record_id,
        "details": details,
        "timestamp": datetime.utcnow()
    }

    result = await audit_logs_collection.insert_one(log)

    print("AUDIT LOG CREATED:", result.inserted_id)
