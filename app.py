# ==================== api.py - BACKEND COMPLET I HUB HOSPITAL ====================
from __future__ import annotations
import json
import os
import secrets
import time
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from flask import Flask, jsonify, request, g, send_file, after_this_request
from flask_cors import CORS
from flask_caching import Cache
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import io

# ==================== CONFIGURATION ====================
SUPABASE_URL = "https://figmeixteescztmmprmi.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-Bwv0EUQzME3nZR8ZPoSwTMCaybHRnw_-7Ew"
SECRET_KEY = secrets.token_hex(32)
GROQ_API_KEY = os.environ.get("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", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))
DEBUG = False
TOKEN_EXPIRY = 86400 * 7  # 7 jours
CACHE_TIMEOUT = 300

# ==================== INITIALISATION ====================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = CACHE_TIMEOUT
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max

cache = Cache(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

if not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY est requis en production")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# ==================== CONSTANTES ====================
TABLES = {
    "users": "app_users",
    "patients": "patients",
    "appointments": "appointments",
    "prescriptions": "prescriptions",
    "lab_tests": "laboratory_tests",
    "lab_results": "lab_results",
    "care": "care_logs",
    "pharmacy": "pharmacy_items",
    "billing": "invoices",
    "audit": "audit_logs",
    "pregnancies": "pregnancies",
    "prenatal_visits": "prenatal_visits",
    "deliveries": "deliveries",
    "vaccinations": "vaccinations",
    "growth_logs": "growth_logs",
    "maternity_rooms": "maternity_rooms",
    "children": "children",
    "notifications": "notifications",
    "departments": "departments",
    "staff_schedule": "staff_schedule",
    "medical_equipment": "medical_equipment"
}

ROLES = {
    "public": ["docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre", "radiologue", "chirurgien"],
    "staff": ["super_admin", "docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre", "radiologue", "chirurgien"],
}

VACCIN_CALENDRIER = {
    "BCG": {"doses": 1, "age_min_mois": 0, "age_max_mois": 1},
    "Hépatite B": {"doses": 3, "age_min_mois": 0, "age_max_mois": 6},
    "DTCP": {"doses": 4, "age_min_mois": 2, "age_max_mois": 18},
    "Hib": {"doses": 3, "age_min_mois": 2, "age_max_mois": 12},
    "Pneumocoque": {"doses": 3, "age_min_mois": 2, "age_max_mois": 12},
    "ROR": {"doses": 2, "age_min_mois": 12, "age_max_mois": 36},
    "Varicelle": {"doses": 2, "age_min_mois": 12, "age_max_mois": 72},
    "HPV": {"doses": 2, "age_min_mois": 132, "age_max_mois": 168}
}

# ==================== UTILITAIRES ====================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def now_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()

def fast_json() -> dict:
    return request.get_json(silent=True) or {}

def to_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def to_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default

def to_bool(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "on")
    return default

def invalidate_cache():
    cache.clear()

def generate_invoice_number() -> str:
    year = datetime.now().strftime("%Y")
    month = datetime.now().strftime("%m")
    random_part = secrets.token_hex(3).upper()
    return f"INV-{year}{month}-{random_part}"

def calculate_age(birth_date: str) -> Dict:
    if not birth_date:
        return {"years": 0, "months": 0, "days": 0, "display": "—"}
    birth = datetime.fromisoformat(birth_date[:10])
    today = datetime.now()
    years = today.year - birth.year
    months = today.month - birth.month
    days = today.day - birth.day
    
    if days < 0:
        months -= 1
        days += (birth.replace(month=birth.month % 12 + 1, day=1) - timedelta(days=1)).day
    if months < 0:
        years -= 1
        months += 12
    
    if years > 0:
        display = f"{years} an{'s' if years > 1 else ''}"
    elif months > 0:
        display = f"{months} mois"
    else:
        display = f"{days} jour{'s' if days > 1 else ''}"
    
    return {"years": years, "months": months, "days": days, "display": display}

# ==================== AUTHENTIFICATION ====================
def create_token(user: dict) -> str:
    payload = {
        "id": user["id"],
        "role": user["role"],
        "email": user["email"],
        "name": user.get("name", ""),
        "exp": int(time.time()) + TOKEN_EXPIRY
    }
    return serializer.dumps(payload)

def decode_token(token: str) -> dict:
    return serializer.loads(token, max_age=TOKEN_EXPIRY)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            token = request.cookies.get("ihub_session", "")
        if not token:
            return jsonify({"error": "Token requis"}), 401
        try:
            payload = decode_token(token)
            cache_key = f"user:{payload['id']}"
            user_data = cache.get(cache_key)
            if user_data is None:
                result = supabase.table(TABLES["users"]).select("*").eq("id", payload["id"]).execute()
                if not result.data:
                    return jsonify({"error": "Utilisateur introuvable"}), 401
                user_data = result.data[0]
                cache.set(cache_key, user_data, CACHE_TIMEOUT)
            g.current_user = user_data
        except SignatureExpired:
            return jsonify({"error": "Token expiré"}), 401
        except Exception:
            return jsonify({"error": "Token invalide"}), 401
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
            "action": action,
            "entity_type": entity,
            "entity_id": entity_id,
            "user_id": g.current_user.get("id") if hasattr(g, 'current_user') else None,
            "user_name": g.current_user.get("name") if hasattr(g, 'current_user') else "Systeme",
            "details": details or "",
            "created_at": now_iso()
        }).execute()
    except Exception as e:
        print(f"Audit error: {e}")

# ==================== ROUTES AUTH ====================
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = fast_json()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    
    result = supabase.table(TABLES["users"]).select("*").eq("email", email).execute()
    user = result.data[0] if result.data else None
    
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        add_audit("LOGIN_FAILED", "user", f"Tentative échouée: {email}")
        return jsonify({"error": "Identifiants incorrects"}), 401
    
    if not user.get("is_active", True):
        return jsonify({"error": "Compte désactivé"}), 401
    
    token = create_token(user)
    add_audit("LOGIN", "user", f"Connexion: {email}", user["id"])
    
    user_response = {k: v for k, v in user.items() if k not in ["password_hash"]}
    return jsonify({"user": user_response, "token": token})

@app.route("/api/auth/register", methods=["POST"])
@roles_required("super_admin")
def register():
    data = fast_json()
    email = data.get("email", "").lower().strip()
    role = data.get("role", "reception")
    
    if role not in ROLES["public"]:
        return jsonify({"error": "Rôle invalide"}), 422
    
    # Vérifier si l'email existe déjà
    existing = supabase.table(TABLES["users"]).select("id").eq("email", email).execute()
    if existing.data:
        return jsonify({"error": "Cet email est déjà utilisé"}), 409
    
    user_data = {
        "name": data.get("name", ""),
        "email": email,
        "password_hash": generate_password_hash(data.get("password", "")),
        "role": role,
        "is_active": True,
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["users"]).insert(user_data).execute()
    user = result.data[0]
    add_audit("CREATE", "user", f"Nouveau compte: {email}", user["id"])
    
    return jsonify({"user": {k: v for k, v in user.items() if k != "password_hash"}, "token": create_token(user)}), 201

@app.route("/api/auth/logout", methods=["POST"])
@token_required
def logout():
    add_audit("LOGOUT", "user", f"Déconnexion: {g.current_user.get('email')}", g.current_user.get("id"))
    return jsonify({"message": "Déconnexion réussie"})

@app.route("/api/auth/me", methods=["GET"])
@token_required
def get_current_user():
    user = {k: v for k, v in g.current_user.items() if k != "password_hash"}
    return jsonify(user)

@app.route("/api/auth/change-password", methods=["POST"])
@token_required
def change_password():
    data = fast_json()
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    
    if not check_password_hash(g.current_user.get("password_hash", ""), old_password):
        return jsonify({"error": "Ancien mot de passe incorrect"}), 401
    
    if len(new_password) < 8:
        return jsonify({"error": "Le nouveau mot de passe doit contenir au moins 8 caractères"}), 422
    
    new_hash = generate_password_hash(new_password)
    supabase.table(TABLES["users"]).update({"password_hash": new_hash, "updated_at": now_iso()}).eq("id", g.current_user["id"]).execute()
    
    add_audit("UPDATE", "user", "Changement de mot de passe", g.current_user["id"])
    invalidate_cache()
    return jsonify({"message": "Mot de passe modifié avec succès"})

# ==================== PATIENTS ====================
@app.route("/api/patients", methods=["GET"])
@token_required
def get_patients():
    search = request.args.get("search", "")
    status = request.args.get("status", "")
    limit = to_int(request.args.get("limit", 100))
    
    query = supabase.table(TABLES["patients"]).select("*")
    
    if search:
        query = query.or_(f"full_name.ilike.%{search}%,phone.ilike.%{search}%,email.ilike.%{search}%")
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).limit(limit).execute()
    patients = result.data or []
    
    # Filtrage par rôle
    role = g.current_user.get("role")
    if role == "pediatre":
        patients = [p for p in patients if calculate_age(p.get("date_of_birth", "")).get("years", 0) < 18]
    elif role == "sage_femme":
        pregnancies = supabase.table(TABLES["pregnancies"]).select("patient_id,status").eq("status", "active").execute().data or []
        pregnant_ids = {str(p.get("patient_id")) for p in pregnancies}
        patients = [p for p in patients if str(p.get("gender", "")).lower() in ("f", "female", "féminin", "femme") and str(p.get("id")) in pregnant_ids]
    elif role == "gynecologue":
        patients = [p for p in patients if str(p.get("gender", "")).lower() in ("f", "female", "féminin", "femme")]
    
    return jsonify(patients)

@app.route("/api/patients/<int:id>", methods=["GET"])
@token_required
def get_patient(id):
    result = supabase.table(TABLES["patients"]).select("*").eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    
    patient = result.data[0]
    patient["age"] = calculate_age(patient.get("date_of_birth", ""))
    return jsonify(patient)

@app.route("/api/patients", methods=["POST"])
@roles_required("super_admin", "reception")
def create_patient():
    data = fast_json()
    
    required = ["full_name"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    patient = {
        "full_name": data.get("full_name"),
        "phone": data.get("phone", ""),
        "email": data.get("email", ""),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", "M"),
        "blood_type": data.get("blood_type"),
        "address": data.get("address", ""),
        "medical_history": data.get("medical_history", ""),
        "allergies": data.get("allergies", ""),
        "emergency_contact": data.get("emergency_contact", ""),
        "emergency_phone": data.get("emergency_phone", ""),
        "insurance_provider": data.get("insurance_provider", ""),
        "insurance_number": data.get("insurance_number", ""),
        "status": data.get("status", "active"),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["patients"]).insert(patient).execute()
    add_audit("CREATE", "patient", f"Nouveau patient: {data.get('full_name')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/patients/<int:id>", methods=["PUT"])
@roles_required("super_admin", "reception")
def update_patient(id):
    data = fast_json()
    allowed_fields = ["full_name", "phone", "email", "date_of_birth", "gender", "blood_type", "address", "medical_history", "allergies", "emergency_contact", "emergency_phone", "insurance_provider", "insurance_number", "status"]
    
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    update_data["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["patients"]).update(update_data).eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    
    add_audit("UPDATE", "patient", f"Modification patient ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/patients/<int:id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_patient(id):
    result = supabase.table(TABLES["patients"]).delete().eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    
    add_audit("DELETE", "patient", f"Suppression patient ID {id}", id)
    invalidate_cache()
    return jsonify({"message": "Patient supprimé"})

@app.route("/api/patients/<int:id>/appointments", methods=["GET"])
@token_required
def get_patient_appointments(id):
    result = supabase.table(TABLES["appointments"]).select("*").eq("patient_id", id).order("date", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/patients/<int:id>/prescriptions", methods=["GET"])
@token_required
def get_patient_prescriptions(id):
    result = supabase.table(TABLES["prescriptions"]).select("*").eq("patient_id", id).order("created_at", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/patients/<int:id>/lab-results", methods=["GET"])
@token_required
def get_patient_lab_results(id):
    results = supabase.table(TABLES["lab_results"]).select("*, laboratory_tests(*)").eq("patient_id", id).order("completed_date", desc=True).execute()
    return jsonify(results.data or [])

# ==================== RENDEZ-VOUS ====================
@app.route("/api/appointments", methods=["GET"])
@token_required
def get_appointments():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    query = supabase.table(TABLES["appointments"]).select("*")
    
    if start_date:
        query = query.gte("date", start_date)
    if end_date:
        query = query.lte("date", end_date)
    
    result = query.order("date", desc=False).execute()
    appointments = result.data or []
    
    # Filtrer selon le rôle
    role = g.current_user.get("role")
    if role in ["gynecologue", "docteur"]:
        appointments = [a for a in appointments if a.get("doctor_id") == g.current_user["id"] or a.get("doctor_name") == g.current_user["name"]]
    
    return jsonify(appointments)

@app.route("/api/appointments", methods=["POST"])
@roles_required("super_admin", "reception", "docteur")
def create_appointment():
    data = fast_json()
    
    required = ["patient_id", "date", "type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    appointment = {
        "patient_id": to_int(data.get("patient_id")),
        "date": data.get("date"),
        "type": data.get("type"),
        "duration": to_int(data.get("duration"), 30),
        "status": data.get("status", "scheduled"),
        "doctor_id": g.current_user.get("id") if data.get("assign_to_self") else data.get("doctor_id"),
        "doctor_name": g.current_user.get("name") if data.get("assign_to_self") else data.get("doctor_name"),
        "notes": data.get("notes", ""),
        "created_by": g.current_user["id"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["appointments"]).insert(appointment).execute()
    add_audit("CREATE", "appointment", f"Nouveau RDV pour patient {data.get('patient_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/appointments/<int:id>", methods=["PUT"])
@token_required
def update_appointment(id):
    data = fast_json()
    allowed_fields = ["date", "type", "duration", "status", "notes", "doctor_id", "doctor_name"]
    
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    update_data["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["appointments"]).update(update_data).eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Rendez-vous introuvable"}), 404
    
    add_audit("UPDATE", "appointment", f"Modification RDV ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/appointments/<int:id>/status", methods=["PATCH"])
@token_required
def update_appointment_status(id):
    data = fast_json()
    status = data.get("status")
    
    if status not in ["scheduled", "completed", "cancelled", "no_show"]:
        return jsonify({"error": "Statut invalide"}), 422
    
    result = supabase.table(TABLES["appointments"]).update({"status": status, "updated_at": now_iso()}).eq("id", id).execute()
    add_audit("UPDATE", "appointment", f"Statut RDV ID {id} -> {status}", id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== PRESCRIPTIONS ====================
@app.route("/api/prescriptions", methods=["GET"])
@token_required
def get_prescriptions():
    patient_id = request.args.get("patient_id")
    status = request.args.get("status")
    
    query = supabase.table(TABLES["prescriptions"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/prescriptions", methods=["POST"])
@roles_required("super_admin", "docteur", "gynecologue", "pediatre")
def create_prescription():
    data = fast_json()
    
    required = ["patient_id", "medication", "dosage"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    prescription = {
        "patient_id": to_int(data.get("patient_id")),
        "medication": data.get("medication"),
        "dosage": data.get("dosage"),
        "frequency": data.get("frequency", ""),
        "duration": data.get("duration", ""),
        "start_date": data.get("start_date", now_date()),
        "end_date": data.get("end_date"),
        "instructions": data.get("instructions", ""),
        "status": data.get("status", "active"),
        "prescribed_by": g.current_user["id"],
        "prescribed_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["prescriptions"]).insert(prescription).execute()
    add_audit("CREATE", "prescription", f"Prescription pour patient {data.get('patient_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/prescriptions/<int:id>", methods=["PUT"])
@roles_required("super_admin", "docteur")
def update_prescription(id):
    data = fast_json()
    allowed_fields = ["medication", "dosage", "frequency", "duration", "start_date", "end_date", "instructions", "status"]
    
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    update_data["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["prescriptions"]).update(update_data).eq("id", id).execute()
    add_audit("UPDATE", "prescription", f"Modification prescription ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== LABORATOIRE ====================
@app.route("/api/laboratory/tests", methods=["GET"])
@token_required
def get_lab_tests():
    patient_id = request.args.get("patient_id")
    status = request.args.get("status")
    
    query = supabase.table(TABLES["lab_tests"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/laboratory/tests", methods=["POST"])
@roles_required("super_admin", "docteur")
def create_lab_test():
    data = fast_json()
    
    required = ["patient_id", "test_type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    test = {
        "patient_id": to_int(data.get("patient_id")),
        "test_type": data.get("test_type"),
        "notes": data.get("notes", ""),
        "status": "pending",
        "requested_by": g.current_user["id"],
        "requested_by_name": g.current_user["name"],
        "request_date": now_iso(),
        "created_at": now_iso()
    }
    
    result = supabase.table(TABLES["lab_tests"]).insert(test).execute()
    add_audit("CREATE", "lab_test", f"Nouvelle analyse: {data.get('test_type')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/laboratory/tests/<int:id>/result", methods=["PUT"])
@roles_required("super_admin", "laboratoire")
def add_lab_result(id):
    data = fast_json()
    
    result_data = {
        "result": data.get("result"),
        "observations": data.get("observations", ""),
        "status": "completed",
        "completed_by": g.current_user["id"],
        "completed_by_name": g.current_user["name"],
        "completed_date": now_iso()
    }
    
    # Mettre à jour le test
    test_result = supabase.table(TABLES["lab_tests"]).update(result_data).eq("id", id).execute()
    
    # Créer une entrée dans lab_results
    supabase.table(TABLES["lab_results"]).insert({
        "test_id": id,
        "patient_id": data.get("patient_id"),
        "test_type": data.get("test_type"),
        "result": data.get("result"),
        "observations": data.get("observations", ""),
        "completed_by": g.current_user["id"],
        "completed_date": now_iso()
    }).execute()
    
    add_audit("UPDATE", "lab_test", f"Ajout résultat pour test ID {id}", id)
    invalidate_cache()
    return jsonify(test_result.data[0])

@app.route("/api/laboratory/results", methods=["GET"])
@token_required
def get_lab_results():
    patient_id = request.args.get("patient_id")
    
    query = supabase.table(TABLES["lab_results"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    
    result = query.order("completed_date", desc=True).execute()
    return jsonify(result.data or [])

# ==================== SOINS (CARE) ====================
@app.route("/api/care", methods=["GET"])
@token_required
def get_care_logs():
    patient_id = request.args.get("patient_id")
    
    query = supabase.table(TABLES["care"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    
    result = query.order("date", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/care", methods=["POST"])
@roles_required("super_admin", "infirmier", "docteur")
def create_care_log():
    data = fast_json()
    
    required = ["patient_id", "care_type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    care = {
        "patient_id": to_int(data.get("patient_id")),
        "care_type": data.get("care_type"),
        "description": data.get("description", ""),
        "performed_by": g.current_user["id"],
        "performed_by_name": g.current_user["name"],
        "date": now_iso(),
        "created_at": now_iso()
    }
    
    result = supabase.table(TABLES["care"]).insert(care).execute()
    add_audit("CREATE", "care", f"Soin pour patient {data.get('patient_id')}: {data.get('care_type')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/care/<int:id>", methods=["PUT"])
@roles_required("super_admin", "infirmier", "docteur")
def update_care_log(id):
    data = fast_json()
    allowed_fields = ["care_type", "description"]
    
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    
    result = supabase.table(TABLES["care"]).update(update_data).eq("id", id).execute()
    add_audit("UPDATE", "care", f"Modification soin ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/care/<int:id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_care_log(id):
    result = supabase.table(TABLES["care"]).delete().eq("id", id).execute()
    add_audit("DELETE", "care", f"Suppression soin ID {id}", id)
    invalidate_cache()
    return jsonify({"message": "Soin supprimé"})

# ==================== PHARMACIE ====================
@app.route("/api/pharmacy", methods=["GET"])
@roles_required("super_admin", "pharmacie")
def get_pharmacy():
    search = request.args.get("search", "")
    low_stock = to_bool(request.args.get("low_stock", False))
    
    query = supabase.table(TABLES["pharmacy"]).select("*")
    
    if search:
        query = query.ilike("medication_name", f"%{search}%")
    if low_stock:
        query = query.lte("quantity", supabase.table(TABLES["pharmacy"]).select("threshold"))
    
    result = query.order("medication_name").execute()
    return jsonify(result.data or [])

@app.route("/api/pharmacy/<int:id>", methods=["GET"])
@roles_required("super_admin", "pharmacie")
def get_pharmacy_item(id):
    result = supabase.table(TABLES["pharmacy"]).select("*").eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Médicament non trouvé"}), 404
    return jsonify(result.data[0])

@app.route("/api/pharmacy", methods=["POST"])
@roles_required("super_admin", "pharmacie")
def create_pharmacy_item():
    data = fast_json()
    
    required = ["medication_name", "quantity", "selling_price"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    item = {
        "medication_name": data.get("medication_name"),
        "quantity": to_int(data.get("quantity")),
        "unit": data.get("unit", "boîte"),
        "purchase_price": to_float(data.get("purchase_price")),
        "selling_price": to_float(data.get("selling_price")),
        "supplier": data.get("supplier", ""),
        "threshold": to_int(data.get("threshold"), 10),
        "expiry_date": data.get("expiry_date"),
        "batch_number": data.get("batch_number", ""),
        "location": data.get("location", ""),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["pharmacy"]).insert(item).execute()
    add_audit("CREATE", "pharmacy", f"Nouveau médicament: {data.get('medication_name')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/pharmacy/<int:id>/stock", methods=["PUT"])
@roles_required("super_admin", "pharmacie")
def update_pharmacy_stock(id):
    data = fast_json()
    operation = data.get("operation")
    quantity = to_int(data.get("quantity"))
    
    current = supabase.table(TABLES["pharmacy"]).select("quantity").eq("id", id).execute()
    if not current.data:
        return jsonify({"error": "Médicament non trouvé"}), 404
    
    current_qty = current.data[0]["quantity"]
    
    if operation == "set":
        new_qty = quantity
    elif operation == "add":
        new_qty = current_qty + quantity
    elif operation == "remove":
        if quantity > current_qty:
            return jsonify({"error": f"Stock insuffisant. Disponible: {current_qty}"}), 400
        new_qty = current_qty - quantity
    else:
        return jsonify({"error": "Opération invalide. Utilisez 'set', 'add' ou 'remove'"}), 400
    
    result = supabase.table(TABLES["pharmacy"]).update({"quantity": new_qty, "updated_at": now_iso()}).eq("id", id).execute()
    
    # Alerte si stock bas
    item = result.data[0]
    if item["quantity"] <= item["threshold"]:
        add_audit("ALERT", "pharmacy", f"Stock bas: {item['medication_name']} ({item['quantity']} restants)", id)
    
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== FACTURATION ====================
@app.route("/api/billing", methods=["GET"])
@roles_required("super_admin", "reception")
def get_invoices():
    patient_id = request.args.get("patient_id")
    status = request.args.get("status")
    
    query = supabase.table(TABLES["billing"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).execute()
    return jsonify(result.data or [])

@app.route("/api/billing", methods=["POST"])
@roles_required("super_admin", "reception")
def create_invoice():
    data = fast_json()
    
    required = ["patient_id", "amount"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    invoice = {
        "invoice_number": generate_invoice_number(),
        "patient_id": to_int(data.get("patient_id")),
        "patient_name": data.get("patient_name", ""),
        "amount": to_float(data.get("amount")),
        "description": data.get("description", ""),
        "items": data.get("items", []),
        "status": data.get("status", "unpaid"),
        "payment_method": data.get("payment_method"),
        "payment_date": data.get("payment_date"),
        "discount": to_float(data.get("discount")),
        "tax": to_float(data.get("tax")),
        "created_by": g.current_user["id"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["billing"]).insert(invoice).execute()
    add_audit("CREATE", "billing", f"Nouvelle facture: {invoice['invoice_number']} - {invoice['amount']} Fc", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/billing/grouped", methods=["POST"])
@roles_required("super_admin", "pharmacie", "reception")
def create_grouped_invoice():
    data = fast_json()
    items = data.get("items", [])
    
    if not items:
        return jsonify({"error": "Aucun article à facturer"}), 422
    
    total = sum(to_float(item.get("amount", to_float(item.get("quantity", 1)) * to_float(item.get("unit_price", 0)))) for item in items)
    
    invoice = {
        "invoice_number": generate_invoice_number(),
        "patient_id": to_int(data.get("patient_id")),
        "amount": total,
        "description": data.get("description", "Facture groupée"),
        "items": items,
        "status": "unpaid",
        "created_by": g.current_user["id"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["billing"]).insert(invoice).execute()
    
    # Mise à jour du stock si source = pharmacy
    if data.get("source") == "pharmacy":
        for item in items:
            med_id = to_int(item.get("medication_id"))
            qty = to_int(item.get("quantity"))
            if med_id and qty:
                current = supabase.table(TABLES["pharmacy"]).select("quantity").eq("id", med_id).execute()
                if current.data:
                    new_qty = max(0, to_int(current.data[0].get("quantity")) - qty)
                    supabase.table(TABLES["pharmacy"]).update({"quantity": new_qty, "updated_at": now_iso()}).eq("id", med_id).execute()
    
    add_audit("CREATE", "billing", f"Facture groupée: {invoice['invoice_number']} - {total} Fc", result.data[0]["id"])
    invalidate_cache()
    return jsonify({"invoice": result.data[0]}), 201

@app.route("/api/billing/<int:id>/pay", methods=["PUT"])
@roles_required("super_admin", "reception")
def pay_invoice(id):
    data = fast_json()
    
    update_data = {
        "status": "paid",
        "payment_method": data.get("payment_method", "cash"),
        "payment_date": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["billing"]).update(update_data).eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Facture introuvable"}), 404
    
    add_audit("UPDATE", "billing", f"Paiement facture ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== MODULE MATERNITÉ ====================
@app.route("/api/maternity/pregnancies", methods=["GET"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue")
def get_pregnancies():
    patient_id = request.args.get("patient_id")
    status = request.args.get("status")
    
    query = supabase.table(TABLES["pregnancies"]).select("*")
    
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).execute()
    pregnancies = result.data or []
    
    # Enrichir avec les noms des patientes
    for p in pregnancies:
        patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", p["patient_id"]).execute()
        p["patient_name"] = patient.data[0]["full_name"] if patient.data else "Inconnu"
    
    return jsonify(pregnancies)

@app.route("/api/maternity/pregnancies", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_pregnancy():
    data = fast_json()
    
    required = ["patient_id", "last_menstrual_period"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    lmp = data.get("last_menstrual_period")
    lmp_date = datetime.fromisoformat(lmp)
    edd = lmp_date + timedelta(days=280)
    
    # Calculer les semaines de gestation
    today = datetime.now()
    gestational_weeks = (today - lmp_date).days // 7
    gestational_days = (today - lmp_date).days % 7
    
    pregnancy = {
        "patient_id": to_int(data.get("patient_id")),
        "last_menstrual_period": lmp,
        "expected_delivery_date": edd.isoformat()[:10],
        "gestational_weeks": gestational_weeks,
        "gestational_days": gestational_days,
        "risk_level": data.get("risk_level", "normal"),
        "medical_history": data.get("medical_history", ""),
        "previous_pregnancies": to_int(data.get("previous_pregnancies")),
        "previous_deliveries": to_int(data.get("previous_deliveries")),
        "notes": data.get("notes", ""),
        "status": "active",
        "created_by": g.current_user["id"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["pregnancies"]).insert(pregnancy).execute()
    add_audit("CREATE", "pregnancy", f"Nouvelle grossesse pour patient {data.get('patient_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/maternity/pregnancies/<int:id>", methods=["GET"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue")
def get_pregnancy(id):
    result = supabase.table(TABLES["pregnancies"]).select("*").eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Grossesse non trouvée"}), 404
    
    pregnancy = result.data[0]
    patient = supabase.table(TABLES["patients"]).select("*").eq("id", pregnancy["patient_id"]).execute()
    pregnancy["patient"] = patient.data[0] if patient.data else None
    
    return jsonify(pregnancy)

@app.route("/api/maternity/pregnancies/<int:id>", methods=["PUT"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def update_pregnancy(id):
    data = fast_json()
    allowed_fields = ["risk_level", "medical_history", "notes", "status"]
    
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    update_data["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["pregnancies"]).update(update_data).eq("id", id).execute()
    add_audit("UPDATE", "pregnancy", f"Modification grossesse ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/maternity/prenatal", methods=["GET"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue")
def get_prenatal_visits():
    pregnancy_id = request.args.get("pregnancy_id")
    patient_id = request.args.get("patient_id")
    
    query = supabase.table(TABLES["prenatal_visits"]).select("*")
    
    if pregnancy_id:
        query = query.eq("pregnancy_id", to_int(pregnancy_id))
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    
    result = query.order("visit_date", desc=True).execute()
    visits = result.data or []
    
    for v in visits:
        patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", v["patient_id"]).execute()
        v["patient_name"] = patient.data[0]["full_name"] if patient.data else "Inconnu"
    
    return jsonify(visits)

@app.route("/api/maternity/prenatal", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_prenatal_visit():
    data = fast_json()
    
    required = ["patient_id", "visit_date"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    visit = {
        "pregnancy_id": data.get("pregnancy_id"),
        "patient_id": to_int(data.get("patient_id")),
        "visit_date": data.get("visit_date"),
        "gestational_weeks": to_int(data.get("gestational_weeks")),
        "weight": to_float(data.get("weight")),
        "blood_pressure": data.get("blood_pressure"),
        "fetal_heart_rate": to_int(data.get("fetal_heart_rate")),
        "fundal_height": to_float(data.get("fundal_height")),
        "presentation": data.get("presentation"),
        "urine_test": data.get("urine_test"),
        "blood_test": data.get("blood_test"),
        "ultrasound_notes": data.get("ultrasound_notes"),
        "vaccinations_given": data.get("vaccinations_given", []),
        "observations": data.get("observations", ""),
        "next_visit_date": data.get("next_visit_date"),
        "performed_by": g.current_user["id"],
        "performed_by_name": g.current_user["name"],
        "created_at": now_iso()
    }
    
    result = supabase.table(TABLES["prenatal_visits"]).insert(visit).execute()
    add_audit("CREATE", "prenatal_visit", f"Consultation prénatale pour patient {data.get('patient_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/maternity/deliveries", methods=["GET"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue")
def get_deliveries():
    result = supabase.table(TABLES["deliveries"]).select("*").order("delivery_date", desc=True).execute()
    deliveries = result.data or []
    
    for d in deliveries:
        patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", d["patient_id"]).execute()
        d["patient_name"] = patient.data[0]["full_name"] if patient.data else "Inconnu"
    
    return jsonify(deliveries)

@app.route("/api/maternity/deliveries", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_delivery():
    data = fast_json()
    
    required = ["patient_id", "delivery_date", "delivery_type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    baby_count = to_int(data.get("baby_count", 1))
    babies_data = data.get("babies", [])
    
    # Enregistrer l'accouchement
    delivery = {
        "pregnancy_id": data.get("pregnancy_id"),
        "patient_id": to_int(data.get("patient_id")),
        "delivery_date": data.get("delivery_date"),
        "delivery_type": data.get("delivery_type"),
        "baby_count": baby_count,
        "presentation": data.get("presentation"),
        "duration_hours": to_float(data.get("duration_hours")),
        "complications": data.get("complications", ""),
        "episiotomy": to_bool(data.get("episiotomy")),
        "perineal_tears": data.get("perineal_tears"),
        "placenta_delivered": to_bool(data.get("placenta_delivered"), True),
        "postpartum_hemorrhage": to_bool(data.get("postpartum_hemorrhage")),
        "observations": data.get("observations", ""),
        "performed_by": g.current_user["id"],
        "performed_by_name": g.current_user["name"],
        "created_at": now_iso()
    }
    
    del_res = supabase.table(TABLES["deliveries"]).insert(delivery).execute()
    delivery_id = del_res.data[0]["id"] if del_res.data else None
    
    # Créer les patients bébés
    babies_created = []
    for i in range(baby_count):
        baby_info = babies_data[i] if i < len(babies_data) else {}
        baby_name = baby_info.get("name", f"Bébé de {data.get('mother_name', 'Inconnue')}")
        
        baby_patient = {
            "full_name": baby_name,
            "date_of_birth": data.get("delivery_date"),
            "gender": baby_info.get("gender", "M"),
            "blood_type": baby_info.get("blood_type"),
            "parent_id": to_int(data.get("patient_id")),
            "birth_weight": to_float(baby_info.get("weight")),
            "apgar_score_1min": to_int(baby_info.get("apgar_1min")),
            "apgar_score_5min": to_int(baby_info.get("apgar_5min")),
            "resuscitation": to_bool(baby_info.get("resuscitation")),
            "observations": baby_info.get("observations", ""),
            "status": "active",
            "created_at": now_iso(),
            "updated_at": now_iso()
        }
        
        baby_res = supabase.table(TABLES["patients"]).insert(baby_patient).execute()
        babies_created.append(baby_res.data[0])
        
        # Ajouter à la table children
        supabase.table(TABLES["children"]).insert({
            "patient_id": baby_res.data[0]["id"],
            "parent_id": to_int(data.get("patient_id")),
            "delivery_id": delivery_id,
            "birth_order": i + 1,
            "birth_weight": to_float(baby_info.get("weight")),
            "created_at": now_iso()
        }).execute()
    
    # Mettre à jour la grossesse comme terminée
    if data.get("pregnancy_id"):
        supabase.table(TABLES["pregnancies"]).update({"status": "completed", "updated_at": now_iso()}).eq("id", data.get("pregnancy_id")).execute()
    
    add_audit("CREATE", "delivery", f"Accouchement + {baby_count} nouveau-né(s) pour patient {data.get('patient_id')}", delivery_id)
    invalidate_cache()
    
    return jsonify({
        "delivery": del_res.data[0] if del_res.data else None,
        "babies": babies_created
    }), 201

@app.route("/api/maternity/deliveries/<int:id>", methods=["GET"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue")
def get_delivery(id):
    result = supabase.table(TABLES["deliveries"]).select("*").eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Accouchement non trouvé"}), 404
    
    delivery = result.data[0]
    
    # Récupérer les bébés
    babies = supabase.table(TABLES["children"]).select("*, patients(*)").eq("delivery_id", id).execute()
    delivery["babies"] = babies.data or []
    
    patient = supabase.table(TABLES["patients"]).select("*").eq("id", delivery["patient_id"]).execute()
    delivery["patient"] = patient.data[0] if patient.data else None
    
    return jsonify(delivery)

# ==================== MODULE PÉDIATRIE ====================
@app.route("/api/pediatrics/children", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_children():
    result = supabase.table(TABLES["children"]).select("*, patients(*)").order("created_at", desc=True).execute()
    children = result.data or []
    
    for child in children:
        if child.get("patients"):
            patient_data = child["patients"]
            child["full_name"] = patient_data.get("full_name")
            child["date_of_birth"] = patient_data.get("date_of_birth")
            child["gender"] = patient_data.get("gender")
            child["blood_type"] = patient_data.get("blood_type")
            child["age"] = calculate_age(patient_data.get("date_of_birth", ""))
    
    return jsonify(children)

@app.route("/api/pediatrics/children", methods=["POST"])
@roles_required("super_admin", "pediatre")
def create_child():
    data = fast_json()
    
    required = ["full_name", "date_of_birth"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    # Créer le patient
    patient = {
        "full_name": data.get("full_name"),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", "M"),
        "blood_type": data.get("blood_type"),
        "allergies": data.get("allergies", ""),
        "medical_history": data.get("medical_history", ""),
        "parent_id": data.get("parent_id"),
        "status": "active",
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    patient_res = supabase.table(TABLES["patients"]).insert(patient).execute()
    patient_id = patient_res.data[0]["id"] if patient_res.data else None
    
    # Créer l'entrée enfant
    child = {
        "patient_id": patient_id,
        "parent_id": data.get("parent_id"),
        "birth_weight": to_float(data.get("birth_weight")),
        "gestational_weeks": to_int(data.get("gestational_weeks")),
        "blood_type": data.get("blood_type"),
        "allergies": data.get("allergies", ""),
        "special_needs": data.get("special_needs", ""),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["children"]).insert(child).execute()
    add_audit("CREATE", "child", f"Nouvel enfant: {data.get('full_name')}", result.data[0]["id"] if result.data else None)
    invalidate_cache()
    
    return jsonify({"child": result.data[0] if result.data else None, "patient": patient_res.data[0]}), 201

@app.route("/api/pediatrics/children/<int:id>", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_child(id):
    result = supabase.table(TABLES["children"]).select("*, patients(*)").eq("id", id).execute()
    if not result.data:
        return jsonify({"error": "Enfant non trouvé"}), 404
    
    child = result.data[0]
    if child.get("patients"):
        child["full_name"] = child["patients"].get("full_name")
        child["date_of_birth"] = child["patients"].get("date_of_birth")
        child["age"] = calculate_age(child["patients"].get("date_of_birth", ""))
    
    # Récupérer les vaccinations
    vaccinations = supabase.table(TABLES["vaccinations"]).select("*").eq("child_id", id).order("administered_date", desc=True).execute()
    child["vaccinations"] = vaccinations.data or []
    
    # Récupérer les mesures de croissance
    growth = supabase.table(TABLES["growth_logs"]).select("*").eq("child_id", id).order("measurement_date", desc=True).execute()
    child["growth_logs"] = growth.data or []
    
    return jsonify(child)

@app.route("/api/pediatrics/children/<int:id>", methods=["PUT"])
@roles_required("super_admin", "pediatre")
def update_child(id):
    data = fast_json()
    
    # Mettre à jour le patient associé
    child_res = supabase.table(TABLES["children"]).select("patient_id").eq("id", id).execute()
    if child_res.data:
        patient_id = child_res.data[0]["patient_id"]
        supabase.table(TABLES["patients"]).update({
            "full_name": data.get("full_name"),
            "blood_type": data.get("blood_type"),
            "allergies": data.get("allergies"),
            "updated_at": now_iso()
        }).eq("id", patient_id).execute()
    
    # Mettre à jour l'enfant
    allowed_fields = ["birth_weight", "blood_type", "allergies", "special_needs"]
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    update_data["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["children"]).update(update_data).eq("id", id).execute()
    add_audit("UPDATE", "child", f"Modification enfant ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== VACCINATIONS ====================
@app.route("/api/pediatrics/vaccinations", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_vaccinations():
    child_id = request.args.get("child_id")
    status = request.args.get("status")
    
    query = supabase.table(TABLES["vaccinations"]).select("*")
    
    if child_id:
        query = query.eq("child_id", to_int(child_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("scheduled_date").execute()
    vaccinations = result.data or []
    
    for v in vaccinations:
        child = supabase.table(TABLES["children"]).select("patient_id").eq("id", v["child_id"]).execute()
        if child.data:
            patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", child.data[0]["patient_id"]).execute()
            v["child_name"] = patient.data[0]["full_name"] if patient.data else "Inconnu"
    
    return jsonify(vaccinations)

@app.route("/api/pediatrics/vaccinations", methods=["POST"])
@roles_required("super_admin", "pediatre")
def create_vaccination():
    data = fast_json()
    
    required = ["child_id", "vaccine_name", "administered_date"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    # Calculer la prochaine date due selon le calendrier
    vaccine_info = VACCIN_CALENDRIER.get(data.get("vaccine_name"))
    next_due_date = None
    if vaccine_info and data.get("dose_number", 1) < vaccine_info["doses"]:
        # Prochaine dose dans 1-2 mois
        next_due = datetime.fromisoformat(data.get("administered_date")) + timedelta(days=60)
        next_due_date = next_due.isoformat()[:10]
    
    vaccination = {
        "child_id": to_int(data.get("child_id")),
        "vaccine_name": data.get("vaccine_name"),
        "dose_number": to_int(data.get("dose_number"), 1),
        "administered_date": data.get("administered_date"),
        "next_due_date": data.get("next_due_date", next_due_date),
        "batch_number": data.get("batch_number", ""),
        "site": data.get("site", "deltoid"),
        "reaction": data.get("reaction", ""),
        "status": "completed",
        "administered_by": g.current_user["id"],
        "administered_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["vaccinations"]).insert(vaccination).execute()
    add_audit("CREATE", "vaccination", f"Vaccination: {data.get('vaccine_name')} pour enfant {data.get('child_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/pediatrics/vaccinations/schedule", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_vaccination_schedule():
    """Retourne le calendrier vaccinal recommandé"""
    return jsonify(VACCIN_CALENDRIER)

# ==================== CROISSANCE ====================
@app.route("/api/pediatrics/growth", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_growth_logs():
    child_id = request.args.get("child_id")
    
    query = supabase.table(TABLES["growth_logs"]).select("*")
    
    if child_id:
        query = query.eq("child_id", to_int(child_id))
    
    result = query.order("measurement_date", desc=True).execute()
    logs = result.data or []
    
    for log in logs:
        child = supabase.table(TABLES["children"]).select("patient_id").eq("id", log["child_id"]).execute()
        if child.data:
            patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", child.data[0]["patient_id"]).execute()
            log["child_name"] = patient.data[0]["full_name"] if patient.data else "Inconnu"
    
    return jsonify(logs)

@app.route("/api/pediatrics/growth", methods=["POST"])
@roles_required("super_admin", "pediatre")
def create_growth_log():
    data = fast_json()
    
    required = ["child_id", "measurement_date"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    # Calculer l'âge en mois
    child = supabase.table(TABLES["children"]).select("patient_id").eq("id", to_int(data.get("child_id"))).execute()
    age_months = None
    if child.data:
        patient = supabase.table(TABLES["patients"]).select("date_of_birth").eq("id", child.data[0]["patient_id"]).execute()
        if patient.data and patient.data[0].get("date_of_birth"):
            birth = datetime.fromisoformat(patient.data[0]["date_of_birth"])
            measurement = datetime.fromisoformat(data.get("measurement_date"))
            age_months = (measurement.year - birth.year) * 12 + (measurement.month - birth.month)
    
    log = {
        "child_id": to_int(data.get("child_id")),
        "measurement_date": data.get("measurement_date"),
        "age_months": age_months,
        "weight": to_float(data.get("weight")),
        "height": to_float(data.get("height")),
        "head_circumference": to_float(data.get("head_circumference")),
        "bmi": to_float(data.get("bmi")),
        "percentile_weight": data.get("percentile_weight"),
        "percentile_height": data.get("percentile_height"),
        "observations": data.get("observations", ""),
        "measured_by": g.current_user["id"],
        "measured_by_name": g.current_user["name"],
        "created_at": now_iso()
    }
    
    result = supabase.table(TABLES["growth_logs"]).insert(log).execute()
    add_audit("CREATE", "growth_log", f"Nouvelle mesure pour enfant {data.get('child_id')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

# ==================== MATERNITY ROOMS ====================
@app.route("/api/maternity/rooms", methods=["GET"])
@roles_required("super_admin", "sage_femme")
def get_maternity_rooms():
    status = request.args.get("status")
    
    query = supabase.table(TABLES["maternity_rooms"]).select("*")
    
    if status:
        query = query.eq("status", status)
    
    result = query.order("room_number").execute()
    rooms = result.data or []
    
    for room in rooms:
        if room.get("patient_id"):
            patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", room["patient_id"]).execute()
            room["patient_name"] = patient.data[0]["full_name"] if patient.data else None
    
    return jsonify(rooms)

@app.route("/api/maternity/rooms", methods=["POST"])
@roles_required("super_admin")
def create_maternity_room():
    data = fast_json()
    
    required = ["room_number"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    room = {
        "room_number": data.get("room_number"),
        "type": data.get("type", "standard"),
        "status": "available",
        "amenities": data.get("amenities", []),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = supabase.table(TABLES["maternity_rooms"]).insert(room).execute()
    add_audit("CREATE", "maternity_room", f"Nouveau lit: {data.get('room_number')}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/maternity/rooms/admit", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def admit_to_maternity_room():
    data = fast_json()
    
    required = ["room_id", "patient_id"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Le champ {field} est requis"}), 422
    
    # Vérifier que la chambre est disponible
    room = supabase.table(TABLES["maternity_rooms"]).select("*").eq("id", to_int(data.get("room_id"))).execute()
    if not room.data or room.data[0]["status"] != "available":
        return jsonify({"error": "Chambre non disponible"}), 400
    
    # Mettre à jour la chambre
    result = supabase.table(TABLES["maternity_rooms"]).update({
        "status": "occupied",
        "patient_id": to_int(data.get("patient_id")),
        "admission_date": now_date(),
        "admission_reason": data.get("reason", ""),
        "updated_at": now_iso()
    }).eq("id", to_int(data.get("room_id"))).execute()
    
    add_audit("UPDATE", "maternity_room", f"Admission patient {data.get('patient_id')} dans chambre {room.data[0]['room_number']}", data.get("room_id"))
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/maternity/rooms/<int:id>/discharge", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def discharge_from_maternity_room(id):
    result = supabase.table(TABLES["maternity_rooms"]).update({
        "status": "available",
        "patient_id": None,
        "discharge_date": now_date(),
        "updated_at": now_iso()
    }).eq("id", id).execute()
    
    add_audit("UPDATE", "maternity_room", f"Libération chambre ID {id}", id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== IA MÉDICALE (GROQ) ====================
AI_DISCLAIMER = "⚠️ Assistant médical uniquement. Toute décision clinique doit être validée par un professionnel de santé habilité."

def groq_chat(system_prompt: str, user_prompt: str) -> Dict:
    if not GROQ_API_KEY:
        return {"error": "IA non configurée. Définir GROQ_API_KEY côté serveur.", "available": False}
    
    payload = json.dumps({
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt + "\n\n" + AI_DISCLAIMER},
            {"role": "user", "content": user_prompt[:15000]}  # Limiter la taille
        ],
        "temperature": 0.2,
        "max_tokens": 1000
    }).encode("utf-8")
    
    try:
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as res:
            data = json.loads(res.read().decode("utf-8"))
            return {"content": data["choices"][0]["message"]["content"], "available": True}
    except Exception as exc:
        return {"error": f"IA temporairement indisponible: {str(exc)}", "available": False}

@app.route("/api/ai/patient-summary", methods=["POST"])
@token_required
def ai_patient_summary():
    data = fast_json()
    patient_id = to_int(data.get("patient_id"))
    
    patient = supabase.table(TABLES["patients"]).select("*").eq("id", patient_id).execute()
    if not patient.data:
        return jsonify({"error": "Patient introuvable"}), 404
    
    # Récupérer les données supplémentaires
    prescriptions = supabase.table(TABLES["prescriptions"]).select("*").eq("patient_id", patient_id).execute()
    appointments = supabase.table(TABLES["appointments"]).select("*").eq("patient_id", patient_id).execute()
    
    context = {
        "patient": patient.data[0],
        "prescriptions": prescriptions.data[:5],
        "recent_appointments": appointments.data[:5]
    }
    
    result = groq_chat(
        "Tu es un assistant médical hospitalier. Rédige un résumé clinique structuré du patient (antécédents, traitements en cours, rendez-vous récents). Ne pose pas de diagnostic final et mentionne toujours les limites de l'IA.",
        json.dumps(context, ensure_ascii=False, default=str)
    )
    
    return jsonify({"summary": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

@app.route("/api/ai/pregnancy-risk", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def ai_pregnancy_risk():
    data = fast_json()
    
    result = groq_chat(
        "Analyse les facteurs de risque de grossesse présentés. Identifie les points de vigilance, suggère des examens complémentaires et des précautions à prendre. Ne donne jamais de diagnostic définitif.",
        json.dumps(data, ensure_ascii=False, default=str)
    )
    
    return jsonify({"analysis": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

@app.route("/api/ai/clinical-decision", methods=["POST"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue", "pediatre")
def ai_clinical_decision():
    data = fast_json()
    context = data.get("context", "")
    
    if len(context) < 20:
        return jsonify({"error": "Contexte clinique insuffisant. Décrivez la situation avec plus de détails."}), 422
    
    result = groq_chat(
        "Aide à l'orientation clinique. Structure ta réponse: 1) Priorités immédiates, 2) Hypothèses à vérifier, 3) Examens recommandés, 4) Signes d'alerte à surveiller, 5) Limites de cette analyse.",
        context
    )
    
    return jsonify({"analysis": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

@app.route("/api/ai/medical-report", methods=["POST"])
@token_required
def ai_medical_report():
    data = fast_json()
    
    result = groq_chat(
        "Génère un rapport médical structuré, factuel et prudent. Mentionne que ce document est une proposition et doit être revu par un médecin.",
        json.dumps(data, ensure_ascii=False, default=str)
    )
    
    return jsonify({"report": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

@app.route("/api/ai/hospital-flow", methods=["POST"])
@token_required
def ai_hospital_flow():
    data = fast_json()
    
    result = groq_chat(
        "Prédis l'affluence hospitalière à court terme à partir des rendez-vous et admissions. Réponds avec: niveaux de charge prévus (faible/moyen/élevé), pics attendus, recommandations opérationnelles pour le personnel.",
        json.dumps(data, ensure_ascii=False, default=str)[:12000]
    )
    
    return jsonify({"prediction": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

@app.route("/api/ai/smart-alerts", methods=["POST"])
@token_required
def ai_smart_alerts():
    data = fast_json()
    
    result = groq_chat(
        "Classe et priorise ces alertes HMIS (stock bas, rendez-vous, DPA proches, etc.). Propose des actions correctives. Ne décide jamais à la place des soignants.",
        json.dumps(data, ensure_ascii=False, default=str)
    )
    
    return jsonify({"analysis": result.get("content"), "disclaimer": AI_DISCLAIMER, "available": result.get("available", False)})

# ==================== RAPPORTS ET STATISTIQUES ====================
@app.route("/api/reports/dashboard", methods=["GET"])
@token_required
def get_dashboard_stats():
    # Patients
    patients = supabase.table(TABLES["patients"]).select("id,status", count="exact").execute()
    total_patients = patients.count if hasattr(patients, 'count') else len(patients.data or [])
    
    # Rendez-vous aujourd'hui
    today = now_date()
    appointments_today = supabase.table(TABLES["appointments"]).select("id", count="exact").eq("date", today).execute()
    
    # Prescriptions actives
    active_prescriptions = supabase.table(TABLES["prescriptions"]).select("id", count="exact").eq("status", "active").execute()
    
    # Analyses en attente
    pending_tests = supabase.table(TABLES["lab_tests"]).select("id", count="exact").eq("status", "pending").execute()
    
    # Factures impayées
    unpaid_invoices = supabase.table(TABLES["billing"]).select("amount", count="exact").eq("status", "unpaid").execute()
    unpaid_amount = sum(inv.get("amount", 0) for inv in (unpaid_invoices.data or []))
    
    # Revenus
    paid_invoices = supabase.table(TABLES["billing"]).select("amount", count="exact").eq("status", "paid").execute()
    revenue = sum(inv.get("amount", 0) for inv in (paid_invoices.data or []))
    
    # Grossesses actives
    active_pregnancies = supabase.table(TABLES["pregnancies"]).select("id", count="exact").eq("status", "active").execute()
    
    return jsonify({
        "total_patients": total_patients,
        "appointments_today": appointments_today.count if hasattr(appointments_today, 'count') else len(appointments_today.data or []),
        "active_prescriptions": active_prescriptions.count if hasattr(active_prescriptions, 'count') else len(active_prescriptions.data or []),
        "pending_tests": pending_tests.count if hasattr(pending_tests, 'count') else len(pending_tests.data or []),
        "unpaid_invoices": unpaid_invoices.count if hasattr(unpaid_invoices, 'count') else len(unpaid_invoices.data or []),
        "unpaid_amount": unpaid_amount,
        "revenue": revenue,
        "active_pregnancies": active_pregnancies.count if hasattr(active_pregnancies, 'count') else len(active_pregnancies.data or [])
    })

# ==================== AUDIT LOGS ====================
@app.route("/api/audit", methods=["GET"])
@roles_required("super_admin")
def get_audit_logs():
    limit = to_int(request.args.get("limit", 100))
    action = request.args.get("action")
    user_id = request.args.get("user_id")
    
    query = supabase.table(TABLES["audit"]).select("*")
    
    if action:
        query = query.eq("action", action)
    if user_id:
        query = query.eq("user_id", to_int(user_id))
    
    result = query.order("created_at", desc=True).limit(limit).execute()
    return jsonify(result.data or [])

# ==================== HEALTH CHECK ====================
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": now_iso(),
        "version": "2.0.0",
        "services": {
            "supabase": "connected" if SUPABASE_KEY else "not_configured",
            "groq": "configured" if GROQ_API_KEY else "not_configured"
        }
    })

# ==================== LANCEMENT ====================
if __name__ == "__main__":
    print("=" * 60)
    print("🏥 I HUB HOSPITAL API V2.0 - COMPLETE")
    print("=" * 60)
    print(f"📡 Serveur: http://{HOST}:{PORT}")
    print(f"🔐 Supabase: {'✅' if SUPABASE_KEY else '❌'}")
    print(f"🧠 Groq IA: {'✅' if GROQ_API_KEY else '❌'}")
    print("=" * 60)
    print("\n📚 ENDPOINTS DISPONIBLES:")
    print("  🔐 Auth: /api/auth/*")
    print("  👤 Patients: /api/patients/*")
    print("  📅 Rendez-vous: /api/appointments/*")
    print("  💊 Prescriptions: /api/prescriptions/*")
    print("  🔬 Laboratoire: /api/laboratory/*")
    print("  💊 Pharmacie: /api/pharmacy/*")
    print("  💰 Facturation: /api/billing/*")
    print("  🤰 Maternité: /api/maternity/*")
    print("  👶 Pédiatrie: /api/pediatrics/*")
    print("  🧠 IA Médicale: /api/ai/*")
    print("=" * 60)
    
    app.run(host=HOST, port=PORT, debug=DEBUG)
