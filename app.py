# APP.PY
from unittest import result

from flask import Flask, request, jsonify, send_file
import pickle
import os
import random
import smtplib
import subprocess
import re
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from detection_engine import predict_url
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "datasets"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
cred = credentials.Certificate("uthm-quishread-firebase-adminsdk-fbsvc-8a04c1071f.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

SENDER_EMAIL = "uthmqrscanner@gmail.com"
SENDER_PASSWORD = "qemtcthcsytpynue"

MODEL_PATH = os.path.join("models", "rf_qr_model.pkl")

with open(
    MODEL_PATH,
    "rb"
) as f:
    model = pickle.load(f)


def send_email_otp(receiver_email, otp):

    try:

        msg = MIMEMultipart()

        msg["From"] = SENDER_EMAIL
        msg["To"] = receiver_email
        msg["Subject"] = "QUISHREAD OTP Verification"

        body = f"""
Hello,

Your OTP code is:

{otp}

This OTP will expire in 5 minutes.

If you did not request this code, please ignore this email.

Regards,
QUISHREAD Security Team
"""

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(
            "smtp.gmail.com",
            587
        )

        server.starttls()

        server.login(
            SENDER_EMAIL,
            SENDER_PASSWORD
        )

        server.sendmail(
            SENDER_EMAIL,
            receiver_email,
            msg.as_string()
        )

        server.quit()

        return True

    except Exception as e:

        print("EMAIL ERROR:", e)

        return False


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    print("REQUEST DATA =", data)

    if not data or "url" not in data:
        return jsonify({
            "error": "Missing 'url' in request body"
        }), 400

    url = data["url"]
    result = predict_url(model, url)

    response = {

        "url": result["url"],

        "mlPrediction": result["ml_result"],
        "finalResult": result["final_status"],

        "ipAddress": result["ipAddress"],

        "urlLength": result["urlLength"],
        "urlProtocol": result["urlProtocol"],
        "urlDomain": result["urlDomain"],

        "urlRegistrar": result["urlRegistrar"],

        "urlCreated": str(result["urlCreated"]),
        "urlUpdated": str(result["urlUpdated"]),
        "urlExpired": str(result["urlExpired"]),

        "urlAge": result["urlAge"],

        "confidence": result["confidence"]
    }

    return jsonify(response)

@app.route("/")
def home():
    return "Flask API is running!"

@app.route("/send-otp", methods=["POST"])
def send_otp():

    data = request.get_json()

    if not data or "email" not in data:
        return jsonify({
            "error": "Email required"
        }), 400

    email = data["email"]
    otp_type = data.get("type", "password_reset")
    user_id = data.get("userID")

    otp = random.randint(100000, 999999)

    email_sent = send_email_otp(
        email,
        otp
    )

    if not email_sent:

        return jsonify({
            "success": False,
            "message": "Failed to send email"
        }), 500

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    db.collection("otp_codes").add({
        "userID": user_id,
        "email": email,
        "otp": str(otp),
        "type": otp_type,
        "used": False,
        "createdAt": datetime.now(timezone.utc),
        "expiresAt": expires_at
    })

    print(f"OTP for {email}: {otp}")

    return jsonify({
        "success": True,
        "message": "OTP sent successfully"
    })

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Missing request body"
        }), 400

    email = data.get("email")
    otp = data.get("otp")
    otp_type = data.get("type")

    if not email or not otp:
        return jsonify({
            "error": "Email and OTP are required"
        }), 400

    docs = db.collection("otp_codes") \
        .where("email", "==", email) \
        .where("otp", "==", str(otp)) \
        .where("type", "==", otp_type) \
        .where("used", "==", False) \
        .stream()

    otp_doc = None

    for doc in docs:
        otp_doc = doc
        break

    if otp_doc is None:
        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400

    otp_data = otp_doc.to_dict()

    if otp_data["expiresAt"] < datetime.now(timezone.utc):
        return jsonify({
            "success": False,
            "message": "OTP has expired"
        }), 400

    otp_doc.reference.update({
        "used": True
    })

    # Defaults for response
    uid = ""
    nickname = ""
    userType = "USER"

    if otp_type in ["email_verification", "password_reset"]:

        # Check if this is an admin first
        admin_doc = None
        admins = db.collection("admins") \
            .where("email", "==", email) \
            .stream()

        for a in admins:
            admin_doc = a
            break

        if admin_doc is not None:
            admin_data = admin_doc.to_dict()
            uid = admin_doc.id
            nickname = admin_data.get("nickname", admin_data.get("fullName", ""))
            userType = "ADMIN"

        else:
            # Prefer userID stored in OTP if available
            user_doc = None
            user_id = otp_data.get("userID")

            if user_id:
                snap = db.collection("users").document(user_id).get()
                if snap.exists:
                    user_doc = snap

            if user_doc is None:
                users = db.collection("users") \
                    .where("email", "==", email) \
                    .stream()
                for u in users:
                    user_doc = u
                    break

            if user_doc is not None:
                user_data = user_doc.to_dict()
                # Determine document reference
                try:
                    # user_doc may be a DocumentSnapshot (from .get()) or a QueryDocumentSnapshot (from .stream())
                    ref = user_doc.reference
                except Exception:
                    # Fallback to document reference by id
                    ref = db.collection("users").document(user_doc.id)

                # Only set isVerified for email verification flow
                if otp_type == "email_verification":
                    ref.update({
                        "isVerified": True
                    })

                uid = user_doc.id
                nickname = user_data.get("nickname", "")

    return jsonify({
        "success": True,
        "message": "OTP verified successfully",
        "uid": uid,
        "email": email,
        "userType": userType,
        "nickname": nickname
    })

@app.route("/upload-dataset", methods=["POST"])
def upload_dataset():

    if "file" not in request.files:

        return jsonify({
            "success": False,
            "message": "No file uploaded"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "success": False,
            "message": "No file selected"
        }), 400

    filename = secure_filename(
        file.filename
    )

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(save_path)
    
    file_size_bytes = os.path.getsize(
        save_path
    )

    file_size_mb = round(
        file_size_bytes / (1024 * 1024),
        2
    )

    dataset_ref = db.collection(
        "dataset"
        ).document()
    
    dataset_ref.set({

        "adminID": "",

        "datasetID": dataset_ref.id,

        "fileName": filename,

        "filePath": save_path,

        "fileSize": f"{file_size_mb} MB",

        "uploadDate": datetime.now(
            timezone.utc
        )

    })

    return jsonify({

        "success": True,

        "datasetID": dataset_ref.id,

        "fileName": filename,

        "filePath": save_path
    })

@app.route("/datasets", methods=["GET"])
def get_datasets():

    datasets = []

    docs = db.collection(
        "dataset"
    ).stream()

    for doc in docs:

        data = doc.to_dict()

        datasets.append(data)

    return jsonify(datasets)

@app.route("/retrain", methods=["POST"])
def retrain():

    print("RETRAIN ENDPOINT HIT")

    data = request.get_json()

    dataset_id = data.get("datasetID")

    doc = db.collection(
        "dataset"
    ).document(
        dataset_id
    ).get()

    if not doc.exists:

        return jsonify({
            "success": False,
            "message": "Dataset not found"
        }), 404
    
    dataset = doc.to_dict()
    
    file_path = dataset["filePath"]

    result = subprocess.run(
    [
        "/root/quishread/venv/bin/python",
        "train.py",
        file_path
    ],
    capture_output=True,
    text=True
    ) 
    print("RETURN CODE =", result.returncode)
    print("STDOUT =", result.stdout)
    print("STDERR =", result.stderr)

    match = re.search(
        r"Testing Accuracy : ([\d.]+)%",
        result.stdout
    )
    
    accuracy = float(
        match.group(1)
    ) if match else 0.0
    
    if result.returncode == 0:
        
        # Deactivate all previous models
        old_models = db.collection(
        "ml_models"
     ).stream()

    for old_model in old_models:

        old_model.reference.update({
            "isActive": False
        })

    model_ref = db.collection(
        "ml_models"
    ).document()

    model_ref.set({

        "modelID": model_ref.id,

        "adminID": dataset.get(
            "adminID",
            ""
        ),

        "nickname": dataset.get(
            "nickname",
            ""
        ),

        "datasetName": dataset.get(
            "fileName",
            ""
        ),

        "filePath": dataset.get(
            "filePath",
            ""
        ),

        "modelName": "Random Forest",

        "accuracy": accuracy,

        "isActive": True,

        "trainedAt": datetime.now(
            timezone.utc
        )

    })
    
    return jsonify({
        
        "success": result.returncode == 0,
        
        "message":
            "Model retrained successfully"
                if result.returncode == 0
                else "Retraining failed",

        "output": result.stdout,

        "error": result.stderr

    })

@app.route("/export-dataset", methods=["POST"])
def export_dataset():

    data = request.get_json()

    merge = data.get(
        "merge",
        False
    )

    result = subprocess.run(
        [
            "python",
            "export_dataset.py",
            str(merge)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        return jsonify({
            "success": False,
            "error": result.stderr
        }), 500

    match = re.search(
        r"CSV File\s*:\s*(.+)",
        result.stdout
    )

    if not match:

        return jsonify({
            "success": False,
            "error": "CSV file not found"
        }), 500

    filename = match.group(1).strip()

    filepath = os.path.join(
        "datasets",
        filename
    )

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)