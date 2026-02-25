from fastapi import FastAPI
from routes import router
from fastapi.middleware.cors import CORSMiddleware
from database import users_deleted_collection, records_deleted_collection

app = FastAPI(
    title="🗃️PO Management API",
    description="Backend API for PR/PO Inventory Management System",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "Login endpoints for Admin and Staff"
        },
        {
            "name": "Records",
            "description": "Active PR/PO Records Management"
        },
        {
            "name": "Records - Deleted",
            "description": "Soft deleted records and restore operations"
        },
        {
            "name": "Staff Management",
            "description": "Admin controls for managing staff accounts"
        },
        {
            "name": "Project Associate Management",
            "description": "Admin controls for managing project associate accounts"
        },
        {
            "name": "Documents",
            "description": "File upload, view and soft delete using Supabase"
        },
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
def root():
    return {"message": "Inventory Backend Running"}


# ✅ CREATE TTL INDEX ON STARTUP
@app.on_event("startup")
async def create_ttl_indexes():
    await users_deleted_collection.create_index(
        "deleted_at",
        expireAfterSeconds=432000  # 5 days
    )

    await records_deleted_collection.create_index(
        "deleted_at",
        expireAfterSeconds=432000  # 5 days
    )

    print("TTL indexes created successfully")