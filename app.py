from __future__ import annotations

import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_caching import Cache
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

# ==================== CONFIGURATION ====================
SUPABASE_URL = "https://figmeixteescztmmprmi.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-Bwv0EUQzME3nZR8ZPoSwTMCaybHRnw_-7Ew"
SECRET_KEY = "ihub_super_secret_key_2024"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))
DEBUG = False
TOKEN_EXPIRY = 86400 * 7  # 7 jours
CACHE_TIMEOUT = 300  # 5 minutes

# ==================== INITIALISATION ====================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = CACHE_TIMEOUT

cache = Cache(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# TABLES ÉTENDUES
TABLES = {
    "users": "app_users",
    "patients": "patients",
    "appointments": "appointments",
    "prescriptions": "prescriptions",
    "lab_tests": "laboratory_tests",
    "care": "care_logs",
    "pharmacy": "pharmacy_items",
    "billing": "invoices",
    "audit": "audit_logs",
    "pregnancies": "pregnancies",
    "prenatal_visits": "prenatal_visits",
    "deliveries": "deliveries",
    "vaccinations": "vaccinations",
    "growth_logs": "growth_logs",
    "maternity_rooms": "maternity_rooms"
}

ROLES = {
    "public": ["docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre", "vaccinateur"],
    "staff": ["super_admin", "docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre", "vaccinateur"],
}

# ==================== UTILITAIRES ====================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def fast_json() -> dict:
    return request.get_json(silent=True) or {}

def to_int(val: Any, default: int = 0) -> int:
    try: return int(val)
    except: return default

def to_float(val: Any, default: float = 0.0) -> float:
    try: return float(val)
    except: return default

def normalize_status(status: str, valid: list, default: str) -> str:
    return status if status in valid else default

def invalidate_cache():
    cache.clear()

# ==================== AUTHENTIFICATION ====================
def create_token(user: dict) -> str:
    payload = {"id": user["id"], "role": user["role"], "email": user["email"], "exp": int(time.time()) + TOKEN_EXPIRY}
    return serializer.dumps(payload)

def decode_token(token: str) -> dict:
    return serializer.loads(token, max_age=TOKEN_EXPIRY)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token: token = request.cookies.get("ihub_session", "")
        if not token: return jsonify({"error": "Token requis"}), 401
        try:
            payload = decode_token(token)
            cache_key = f"user:{payload['id']}"
            user_data = cache.get(cache_key)
            if user_data is None:
                result = supabase.table(TABLES["users"]).select("*").eq("id", payload["id"]).execute()
                if not result.data: return jsonify({"error": "Utilisateur introuvable"}), 401
                user_data = result.data[0]
                cache.set(cache_key, user_data, CACHE_TIMEOUT)
            g.current_user = user_data
        except: return jsonify({"error": "Token invalide"}), 401
        return f(*args, **kwargs)
    return decorated

def roles_required(*allowed):
    def decorator(f):
        @token_required
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.current_user.get("role") not in allowed:
                return jsonify({"error": "Accès interdit"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def add_audit(action: str, entity: str, details: str = None, entity_id: int = None):
    try:
        supabase.table(TABLES["audit"]).insert({
            "action": action, "entity_type": entity, "entity_id": entity_id,
            "user_id": g.current_user.get("id") if hasattr(g, 'current_user') else None,
            "user_name": g.current_user.get("name") if hasattr(g, 'current_user') else "Systeme",
            "details": details or "", "created_at": now_iso()
        }).execute()
    except: pass

# ==================== ROUTES AUTH ====================
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = fast_json()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    if not email or not password: return jsonify({"error": "Email et mot de passe requis"}), 422
    result = supabase.table(TABLES["users"]).select("*").eq("email", email).execute()
    user = result.data[0] if result.data else None
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401
    token = create_token(user)
    add_audit("LOGIN", "user", f"Connexion: {email}", user["id"])
    return jsonify({"user": {k: v for k, v in user.items() if k != "password_hash"}, "token": token})

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = fast_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    role = data.get("role", "reception")
    if len(name) < 2: return jsonify({"error": "Nom trop court"}), 422
    if role not in ROLES["public"]: return jsonify({"error": "Rôle invalide"}), 422
    user_data = {"name": name, "email": email, "password_hash": generate_password_hash(password), "role": role, "is_active": True, "created_at": now_iso(), "updated_at": now_iso()}
    result = supabase.table(TABLES["users"]).insert(user_data).execute()
    user = result.data[0]
    return jsonify({"user": {k: v for k, v in user.items() if k != "password_hash"}, "token": create_token(user)}), 201

# ==================== PATIENTS (DÉTAILLÉ) ====================
@app.route("/api/patients", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patients():
    search = request.args.get("search", "").strip().lower()
    if search:
        result = supabase.table(TABLES["patients"]).select("*").or_(f"full_name.ilike.%{search}%,phone.ilike.%{search}%,email.ilike.%{search}%").order("created_at", desc=True).execute()
    else:
        result = supabase.table(TABLES["patients"]).select("*").order("created_at", desc=True).execute()
    return jsonify(result.data)

@app.route("/api/patients", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception", "sage_femme", "pediatre")
def create_patient():
    data = fast_json()
    full_name = data.get("full_name", "").strip()
    if not full_name: return jsonify({"error": "Nom requis"}), 422
    patient = {
        "full_name": full_name, "phone": data.get("phone", ""), "email": data.get("email", ""),
        "date_of_birth": data.get("date_of_birth"), "gender": data.get("gender", ""),
        "blood_type": data.get("blood_type", ""), "address": data.get("address", ""),
        "status": data.get("status", "active"), "allergies": data.get("allergies", ""),
        "medical_history": data.get("medical_history", ""), "emergency_contact": data.get("emergency_contact", ""),
        "insurance": data.get("insurance", ""), "priority": data.get("priority", "normal"),
        "doctor_notes": data.get("doctor_notes", ""), "room_number": data.get("room_number", ""),
        "parent_id": data.get("parent_id"), # Pour lier bébé à maman
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["patients"]).insert(patient).execute()
    add_audit("CREATE", "patient", f"Patient: {full_name}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/patients/<int:patient_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patient(patient_id: int):
    result = supabase.table(TABLES["patients"]).select("*").eq("id", patient_id).execute()
    if not result.data: return jsonify({"error": "Patient introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/patients/<int:patient_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
def update_patient(patient_id: int):
    data = fast_json()
    allowed = ["full_name", "phone", "email", "date_of_birth", "gender", "blood_type", "address", "status", "allergies", "medical_history", "emergency_contact", "insurance", "priority", "doctor_notes", "room_number"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    updates["updated_at"] = now_iso()
    result = supabase.table(TABLES["patients"]).update(updates).eq("id", patient_id).execute()
    add_audit("UPDATE", "patient", f"Patient #{patient_id} modifié", patient_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/patients/<int:patient_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_patient(patient_id: int):
    supabase.table(TABLES["patients"]).delete().eq("id", patient_id).execute()
    add_audit("DELETE", "patient", f"Patient #{patient_id} supprimé", patient_id)
    invalidate_cache()
    return jsonify({"message": "Patient supprimé"})

# ==================== MODULE MATERNITÉ (DÉTAILLÉ) ====================
@app.route("/api/maternity/pregnancies", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def get_pregnancies():
    res = supabase.table(TABLES["pregnancies"]).select("*, patients(full_name)").execute()
    return jsonify(res.data)

@app.route("/api/maternity/pregnancies", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_pregnancy():
    data = fast_json()
    ddr = data.get("ddr")
    dpa = (datetime.fromisoformat(ddr) + timedelta(days=280)).isoformat() if ddr else None
    preg = {
        "patient_id": to_int(data.get("patient_id")), "ddr": ddr, "dpa_estimated": dpa,
        "gestational_age_weeks": to_int(data.get("weeks")), "risk_level": data.get("risk_level", "low"),
        "notes": data.get("notes", ""), "status": "active", "created_at": now_iso()
    }
    result = supabase.table(TABLES["pregnancies"]).insert(preg).execute()
    add_audit("CREATE", "pregnancy", f"Grossesse patient #{data.get('patient_id')}", result.data[0]["id"])
    return jsonify(result.data[0]), 201

@app.route("/api/maternity/prenatal", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def create_prenatal():
    data = fast_json()
    visit = {
        "pregnancy_id": to_int(data.get("pregnancy_id")), "visit_date": now_iso(),
        "weight": to_float(data.get("weight")), "blood_pressure": data.get("blood_pressure"),
        "fetal_heart_rate": data.get("fetal_heart_rate"), "observations": data.get("observations"),
        "created_at": now_iso()
    }
    result = supabase.table(TABLES["prenatal_visits"]).insert(visit).execute()
    return jsonify(result.data[0]), 201

@app.route("/api/maternity/deliveries", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def create_delivery():
    data = fast_json()
    delivery = {
        "pregnancy_id": to_int(data.get("pregnancy_id")), "patient_id": to_int(data.get("patient_id")),
        "delivery_date": data.get("delivery_date", now_iso()), "delivery_type": data.get("delivery_type"),
        "baby_gender": data.get("baby_gender"), "baby_weight": to_float(data.get("baby_weight")),
        "apgar_score": data.get("apgar_score"), "complications": data.get("complications", ""), "created_at": now_iso()
    }
    res_del = supabase.table(TABLES["deliveries"]).insert(delivery).execute()
    
    # Création auto bébé
    baby = {
        "full_name": f"Bébé de {data.get('mother_name')}", "date_of_birth": data.get("delivery_date"),
        "gender": data.get("baby_gender"), "parent_id": to_int(data.get("patient_id")),
        "status": "active", "created_at": now_iso()
    }
    supabase.table(TABLES["patients"]).insert(baby).execute()
    invalidate_cache()
    return jsonify(res_del.data[0]), 201

# ==================== MODULE PÉDIATRIE (DÉTAILLÉ) ====================
@app.route("/api/pediatrics/vaccinations", methods=["GET"])
@roles_required("super_admin", "pediatre", "vaccinateur")
def get_vaccinations():
    res = supabase.table(TABLES["vaccinations"]).select("*, patients(full_name)").execute()
    return jsonify(res.data)

@app.route("/api/pediatrics/vaccinations", methods=["POST"])
@roles_required("super_admin", "pediatre", "vaccinateur")
def add_vaccine():
    data = fast_json()
    vaccine = {
        "patient_id": to_int(data.get("patient_id")), "vaccine_name": data.get("vaccine_name"),
        "dose_number": to_int(data.get("dose_number", 1)), "administered_date": now_iso(),
        "administered_by": g.current_user["name"], "status": "completed", "created_at": now_iso()
    }
    result = supabase.table(TABLES["vaccinations"]).insert(vaccine).execute()
    return jsonify(result.data[0]), 201

@app.route("/api/pediatrics/growth", methods=["POST"])
@roles_required("super_admin", "pediatre")
def add_growth():
    data = fast_json()
    log = {
        "patient_id": to_int(data.get("patient_id")), "weight": to_float(data.get("weight")),
        "height": to_float(data.get("height")), "head_circumference": to_float(data.get("head_circumference")),
        "date": now_iso(), "created_at": now_iso()
    }
    result = supabase.table(TABLES["growth_logs"]).insert(log).execute()
    return jsonify(result.data[0]), 201

# ==================== APPOINTMENTS (FULL) ====================
@app.route("/api/appointments", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_appointments():
    res = supabase.table(TABLES["appointments"]).select("*, patients(full_name)").order("date", desc=True).execute()
    return jsonify(res.data)

@app.route("/api/appointments", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
def create_appointment():
    data = fast_json()
    apt = {
        "patient_id": to_int(data.get("patient_id")), "date": data.get("date"), "type": data.get("type"),
        "notes": data.get("notes", ""), "status": "scheduled", "doctor_name": g.current_user["name"], "created_at": now_iso()
    }
    result = supabase.table(TABLES["appointments"]).insert(apt).execute()
    return jsonify(result.data[0]), 201

# ==================== LABORATOIRE (FULL) ====================
@app.route("/api/laboratory/tests", methods=["GET"])
@token_required
def get_lab_tests():
    res = supabase.table(TABLES["lab_tests"]).select("*, patients(full_name)").order("request_date", desc=True).execute()
    return jsonify(res.data)

@app.route("/api/laboratory/tests", methods=["POST"])
@roles_required("super_admin", "docteur", "laboratoire")
def create_lab_test():
    data = fast_json()
    test = {
        "patient_id": to_int(data.get("patient_id")), "test_type": data.get("test_type"),
        "status": "pending", "request_date": now_iso(), "requested_by": g.current_user["name"], "created_at": now_iso()
    }
    result = supabase.table(TABLES["lab_tests"]).insert(test).execute()
    return jsonify(result.data[0]), 201

@app.route("/api/laboratory/tests/<int:id>/result", methods=["PUT"])
@roles_required("super_admin", "laboratoire")
def update_lab_result(id):
    data = fast_json()
    updates = {"result": data.get("result"), "observations": data.get("observations"), "status": "completed", "completed_date": now_iso(), "technician_name": g.current_user["name"]}
    res = supabase.table(TABLES["lab_tests"]).update(updates).eq("id", id).execute()
    return jsonify(res.data[0])

# ==================== PHARMACIE (FULL V2) ====================
@app.route("/api/pharmacy", methods=["GET"])
@token_required
def get_pharmacy():
    res = supabase.table(TABLES["pharmacy"]).select("*").order("medication_name").execute()
    return jsonify(res.data)

@app.route("/api/pharmacy", methods=["POST"])
@roles_required("super_admin", "pharmacie")
def create_pharmacy_item():
    data = fast_json()
    item = {
        "medication_name": data.get("medication_name"), "quantity": to_int(data.get("quantity")),
        "unit": data.get("unit"), "purchase_price": to_float(data.get("purchase_price")),
        "selling_price": to_float(data.get("selling_price")), "supplier": data.get("supplier"),
        "threshold": to_int(data.get("threshold", 10)), "expiry_date": data.get("expiry_date"),
        "created_at": now_iso(), "updated_at": now_iso()
    }
    res = supabase.table(TABLES["pharmacy"]).insert(item).execute()
    return jsonify(res.data[0]), 201

@app.route("/api/pharmacy/<int:id>/stock", methods=["PUT"])
@roles_required("super_admin", "pharmacie")
def update_stock(id):
    data = fast_json()
    qty = to_int(data.get("quantity"))
    res = supabase.table(TABLES["pharmacy"]).update({"quantity": qty, "updated_at": now_iso()}).eq("id", id).execute()
    return jsonify(res.data[0])

# ==================== BILLING (FULL) ====================
@app.route("/api/billing", methods=["GET"])
@roles_required("super_admin", "reception")
def get_billing():
    res = supabase.table(TABLES["billing"]).select("*, patients(full_name)").order("created_at", desc=True).execute()
    return jsonify(res.data)

@app.route("/api/billing", methods=["POST"])
@roles_required("super_admin", "reception")
def create_billing():
    data = fast_json()
    invoice = {
        "invoice_number": f"FAC-{int(time.time())}", "patient_id": to_int(data.get("patient_id")),
        "amount": to_float(data.get("amount")), "description": data.get("description"),
        "status": "unpaid", "created_by": g.current_user["name"], "created_at": now_iso()
    }
    res = supabase.table(TABLES["billing"]).insert(invoice).execute()
    return jsonify(res.data[0]), 201

# ==================== USERS & SYSTEM ====================
@app.route("/api/users", methods=["GET"])
@roles_required("super_admin")
def get_users():
    res = supabase.table(TABLES["users"]).select("id, name, email, role, is_active").execute()
    return jsonify(res.data)

@app.route("/api/audit", methods=["GET"])
@roles_required("super_admin")
def get_audit():
    res = supabase.table(TABLES["audit"]).select("*").order("created_at", desc=True).limit(500).execute()
    return jsonify(res.data)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "2.5.0", "timestamp": now_iso()})

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
