from fastapi import FastAPI
from routes import router
from fastapi.middleware.cors import CORSMiddleware
from database import users_deleted_collection, records_deleted_collection

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://localhost:5173"]
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