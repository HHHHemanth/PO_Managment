import os
import certifi
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URL = os.getenv("MONGO_URL")

client = AsyncIOMotorClient(
    MONGO_URL,
    tls=True,
    tlsCAFile=certifi.where()
)

db = client.inventory_management_db

users_collection = db.users
records_collection = db.records
audit_logs_collection = db.audit_logs
