import os
import certifi
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URL = os.getenv("MONGO_URL")

client = AsyncIOMotorClient(
    MONGO_URL,
    tls=True,
    tlsCAFile=certifi.where(),
    tlsAllowInvalidCertificates=False,
    serverSelectionTimeoutMS=30000,
    connectTimeoutMS=30000,
    socketTimeoutMS=30000
)

# Force connection on startup
try:
    client.admin.command('ping')
    print("MongoDB connected successfully")
except Exception as e:
    print("MongoDB connection error:", e)

db = client.inventory_management_db

users_collection = db.users
records_collection = db.records
audit_logs_collection = db.audit_logs
