# CREATE_ADMIN.PY
from firebase_admin import credentials, firestore
import firebase_admin
import bcrypt
import base64
import os

cred = credentials.Certificate(
    "uthm-quishread-firebase-adminsdk-fbsvc-8a04c1071f.json"
)

firebase_admin.initialize_app(cred)

db = firestore.client()

# =====================
# ADMIN INFO
# =====================

email = input("Enter admin email: ").strip()
password = input("Enter admin password: ").strip()
full_name = input("Enter full name: ").strip()
nickname = input("Enter nickname: ").strip()

# =====================
# HASH PASSWORD
# =====================

salt = base64.b64encode(
    os.urandom(32)
).decode()

hashed_password = bcrypt.hashpw(
    (password + salt).encode(),
    bcrypt.gensalt()
).decode()

# =====================
# CREATE ADMIN
# =====================

admin_ref = db.collection("admins").document()

admin_ref.set({
    "adminID": admin_ref.id,
    "fullName": full_name,
    "nickname": nickname,
    "email": email,
    "passwordHash": hashed_password,
    "passwordSalt": salt,
    "failedAttempt": 0,
    "lockoutUntil": None,
    "statusActive": True,
    "createdAt": firestore.SERVER_TIMESTAMP,
    "updatedAt": firestore.SERVER_TIMESTAMP
})

print("ADMIN CREATED")
print("ADMIN ID =", admin_ref.id)