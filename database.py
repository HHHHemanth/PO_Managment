import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")

client = AsyncIOMotorClient(MONGO_URL)

db = client.inventory_management_db

users_collection = db.users
records_collection = db.records
audit_logs_collection = db.audit_logs
