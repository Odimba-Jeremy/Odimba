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

# Tables
TABLES = {
    "users": "app_users",
    "patients": "patients",
    "appointments": "appointments",
    "prescriptions": "prescriptions",
    "lab_tests": "laboratory_tests",
    "care": "care_logs",
    "pharmacy": "pharmacy_items",
    "billing": "invoices",
    "audit": "audit_logs"
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
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def to_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default

def normalize_status(status: str, valid: list, default: str) -> str:
    return status if status in valid else default

def invalidate_cache(pattern: str = None):
    """Invalide tout le cache"""
    cache.clear()


# ==================== CACHE INTELLIGENT ====================
def cached(timeout=CACHE_TIMEOUT, key_prefix=None):
    """Décorateur de cache avec invalidation automatique sur modification"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cache_key = key_prefix or f"{f.__name__}:{request.full_path}"
            cached_data = cache.get(cache_key)
            if cached_data is not None:
                return jsonify(cached_data)
            
            result = f(*args, **kwargs)
            if result and hasattr(result, 'get_json'):
                data = result.get_json()
                if data:
                    cache.set(cache_key, data, timeout)
            return result
        return decorated
    return decorator


# ==================== AUTHENTIFICATION ====================
def create_token(user: dict) -> str:
    payload = {
        "id": user["id"], 
        "role": user["role"], 
        "email": user["email"], 
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
        except (SignatureExpired, BadSignature):
            return jsonify({"error": "Token invalide ou expiré"}), 401
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
    """Ajoute un log d'audit (asynchrone, ne bloque pas)"""
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
    except:
        pass


# ==================== ROUTES AUTH ====================
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = fast_json()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"error": "Email et mot de passe requis"}), 422
    
    result = supabase.table(TABLES["users"]).select("*").eq("email", email).execute()
    user = result.data[0] if result.data else None
    
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401
    
    token = create_token(user)
    add_audit("LOGIN", "user", f"Connexion: {email}", user["id"])
    
    return jsonify({
        "user": {k: v for k, v in user.items() if k not in ["password_hash"]},
        "token": token
    })

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = fast_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    role = data.get("role", "reception")
    
    if len(name) < 2:
        return jsonify({"error": "Nom trop court"}), 422
    if "@" not in email:
        return jsonify({"error": "Email invalide"}), 422
    if len(password) < 8:
        return jsonify({"error": "Mot de passe trop court"}), 422
    if role not in ROLES["public"]:
        return jsonify({"error": "Rôle invalide"}), 422
    
    existing = supabase.table(TABLES["users"]).select("id").eq("email", email).execute()
    if existing.data:
        return jsonify({"error": "Email déjà utilisé"}), 422
    
    user_data = {
        "name": name, 
        "email": email, 
        "password_hash": generate_password_hash(password),
        "role": role, 
        "is_active": True, 
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["users"]).insert(user_data).execute()
    user = result.data[0]
    token = create_token(user)
    add_audit("CREATE", "user", f"Inscription: {email}", user["id"])
    invalidate_cache()
    
    return jsonify({
        "user": {k: v for k, v in user.items() if k != "password_hash"}, 
        "token": token
    }), 201

@app.route("/api/auth/logout", methods=["POST"])
@token_required
def logout():
    add_audit("LOGOUT", "user", f"Déconnexion: {g.current_user.get('email')}", g.current_user.get("id"))
    return jsonify({"message": "Déconnexion réussie"})

@app.route("/api/auth/me", methods=["GET"])
@token_required
def auth_me():
    return jsonify({"user": {k: v for k, v in g.current_user.items() if k != "password_hash"}})


# ==================== PATIENTS ====================
@app.route("/api/patients", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(CACHE_TIMEOUT)
def get_patients():
    search = request.args.get("search", "").strip().lower()
    
    if search:
        result = supabase.table(TABLES["patients"]).select("*")\
            .or_(f"full_name.ilike.%{search}%,phone.ilike.%{search}%,email.ilike.%{search}%")\
            .order("created_at", desc=True).execute()
    else:
        result = supabase.table(TABLES["patients"]).select("*").order("created_at", desc=True).execute()
    
    return jsonify(result.data)

@app.route("/api/patients", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception", "sage_femme", "gynecologue")
def create_patient():
    data = fast_json()
    full_name = data.get("full_name", "").strip()
    if not full_name:
        return jsonify({"error": "Nom requis"}), 422
    
    patient = {
        "full_name": full_name,
        "phone": data.get("phone", ""),
        "email": data.get("email", ""),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", ""),
        "blood_type": data.get("blood_type", ""),
        "address": data.get("address", ""),
        "status": data.get("status", "active"),
        "allergies": data.get("allergies", ""),
        "medical_history": data.get("medical_history", ""),
        "emergency_contact": data.get("emergency_contact", ""),
        "insurance": data.get("insurance", ""),
        "priority": data.get("priority", "normal"),
        "doctor_notes": data.get("doctor_notes", ""),
        "room_number": data.get("room_number", ""),
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["patients"]).insert(patient).execute()
    add_audit("CREATE", "patient", f"Patient: {full_name}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/patients/<int:patient_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patient(patient_id: int):
    result = supabase.table(TABLES["patients"]).select("*").eq("id", patient_id).execute()
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/patients/<int:patient_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception", "sage_femme", "gynecologue")
def update_patient(patient_id: int):
    data = fast_json()
    allowed_fields = ["full_name", "phone", "email", "date_of_birth", "gender", "blood_type", 
                      "address", "status", "allergies", "medical_history", "emergency_contact", 
                      "insurance", "priority", "doctor_notes", "room_number"]
    updates = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
    updates["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["patients"]).update(updates).eq("id", patient_id).execute()
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    add_audit("UPDATE", "patient", f"Patient #{patient_id} modifié", patient_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/patients/<int:patient_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_patient(patient_id: int):
    patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", patient_id).execute()
    if not patient.data:
        return jsonify({"error": "Patient introuvable"}), 404
    
    supabase.table(TABLES["patients"]).delete().eq("id", patient_id).execute()
    add_audit("DELETE", "patient", f"Patient: {patient.data[0]['full_name']}", patient_id)
    invalidate_cache()
    return jsonify({"message": "Patient supprimé"})

@app.route("/api/patients/<int:patient_id>/appointments", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patient_appointments(patient_id: int):
    result = supabase.table(TABLES["appointments"]).select("*").eq("patient_id", patient_id).order("date", desc=True).execute()
    return jsonify(result.data)

@app.route("/api/patients/<int:patient_id>/prescriptions", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patient_prescriptions(patient_id: int):
    result = supabase.table(TABLES["prescriptions"]).select("*").eq("patient_id", patient_id).order("created_at", desc=True).execute()
    return jsonify(result.data)

@app.route("/api/patients/<int:patient_id>/lab-results", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_patient_lab_results(patient_id: int):
    result = supabase.table(TABLES["lab_tests"]).select("*").eq("patient_id", patient_id).eq("status", "completed").order("completed_date", desc=True).execute()
    return jsonify(result.data)


# ==================== APPOINTMENTS ====================
@app.route("/api/appointments", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_appointments():
    status = request.args.get("status")
    patient_id = request.args.get("patient_id")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    
    query = supabase.table(TABLES["appointments"]).select("*")
    
    if status:
        query = query.eq("status", status)
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if date_from:
        query = query.gte("date", date_from)
    if date_to:
        query = query.lte("date", date_to)
    
    result = query.order("date", desc=True).execute()
    appointments = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for apt in appointments:
        apt["patient_name"] = patient_map.get(apt.get("patient_id"), "Inconnu")
    
    return jsonify(appointments)

@app.route("/api/appointments", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception", "gynecologue", "pediatre")
def create_appointment():
    data = fast_json()
    required = ["patient_id", "date", "type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Champ {field} requis"}), 422
    
    appointment = {
        "patient_id": to_int(data.get("patient_id")),
        "date": data.get("date"),
        "type": data.get("type"),
        "duration": to_int(data.get("duration"), 30),
        "notes": data.get("notes", ""),
        "status": normalize_status(data.get("status", "scheduled"), ["scheduled", "completed", "cancelled"], "scheduled"),
        "priority": normalize_status(data.get("priority", "normal"), ["normal", "urgent"], "normal"),
        "doctor_id": g.current_user["id"],
        "doctor_name": g.current_user["name"],
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["appointments"]).insert(appointment).execute()
    add_audit("CREATE", "appointment", f"RDV #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/appointments/<int:appointment_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_appointment(appointment_id: int):
    result = supabase.table(TABLES["appointments"]).select("*").eq("id", appointment_id).execute()
    if not result.data:
        return jsonify({"error": "Rendez-vous introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/appointments/<int:appointment_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception", "gynecologue", "pediatre")
def update_appointment(appointment_id: int):
    data = fast_json()
    allowed = ["date", "type", "duration", "status", "priority", "notes"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    if "status" in updates:
        updates["status"] = normalize_status(updates["status"], ["scheduled", "completed", "cancelled"], "scheduled")
    updates["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["appointments"]).update(updates).eq("id", appointment_id).execute()
    if not result.data:
        return jsonify({"error": "Rendez-vous introuvable"}), 404
    add_audit("UPDATE", "appointment", f"RDV #{appointment_id} modifié", appointment_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/appointments/<int:appointment_id>", methods=["PATCH"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
def patch_appointment(appointment_id: int):
    data = fast_json()
    allowed = ["status", "date", "type", "duration", "priority", "notes"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    
    if "status" in updates:
        updates["status"] = normalize_status(updates["status"], ["scheduled", "completed", "cancelled"], "scheduled")
    
    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour"}), 422
    
    updates["updated_at"] = now_iso()
    result = supabase.table(TABLES["appointments"]).update(updates).eq("id", appointment_id).execute()
    
    if not result.data:
        return jsonify({"error": "Rendez-vous introuvable"}), 404
    
    add_audit("UPDATE", "appointment", f"RDV #{appointment_id} modifié (PATCH)", appointment_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/appointments/<int:appointment_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_appointment(appointment_id: int):
    supabase.table(TABLES["appointments"]).delete().eq("id", appointment_id).execute()
    add_audit("DELETE", "appointment", f"RDV #{appointment_id} supprimé", appointment_id)
    invalidate_cache()
    return jsonify({"message": "Rendez-vous supprimé"})


# ==================== PRESCRIPTIONS ====================
@app.route("/api/prescriptions", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(120)
def get_prescriptions():
    result = supabase.table(TABLES["prescriptions"]).select("*").order("created_at", desc=True).execute()
    prescriptions = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for p in prescriptions:
        p["patient_name"] = patient_map.get(p.get("patient_id"), "Inconnu")
    
    return jsonify(prescriptions)

@app.route("/api/prescriptions", methods=["POST"])
@roles_required("super_admin", "docteur", "gynecologue", "pediatre")
def create_prescription():
    data = fast_json()
    if not data.get("patient_id") or not data.get("medication"):
        return jsonify({"error": "Patient et médicament requis"}), 422
    
    prescription = {
        "patient_id": to_int(data.get("patient_id")),
        "medication": data.get("medication"),
        "dosage": data.get("dosage", ""),
        "frequency": data.get("frequency", ""),
        "duration": data.get("duration", ""),
        "start_date": data.get("start_date"),
        "end_date": data.get("end_date"),
        "instructions": data.get("instructions", ""),
        "status": data.get("status", "active"),
        "doctor_id": g.current_user["id"],
        "doctor_name": g.current_user["name"],
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["prescriptions"]).insert(prescription).execute()
    add_audit("CREATE", "prescription", f"Prescription #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/prescriptions/<int:prescription_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "gynecologue", "pediatre")
def update_prescription(prescription_id: int):
    data = fast_json()
    allowed = ["medication", "dosage", "frequency", "duration", "start_date", "end_date", "instructions", "status"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    updates["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["prescriptions"]).update(updates).eq("id", prescription_id).execute()
    if not result.data:
        return jsonify({"error": "Prescription introuvable"}), 404
    add_audit("UPDATE", "prescription", f"Prescription #{prescription_id} modifiée", prescription_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/prescriptions/<int:prescription_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_prescription(prescription_id: int):
    supabase.table(TABLES["prescriptions"]).delete().eq("id", prescription_id).execute()
    add_audit("DELETE", "prescription", f"Prescription #{prescription_id} supprimée", prescription_id)
    invalidate_cache()
    return jsonify({"message": "Prescription supprimée"})


# ==================== LABORATORY ====================
@app.route("/api/laboratory/tests", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_lab_tests():
    status = request.args.get("status")
    patient_id = request.args.get("patient_id")
    
    query = supabase.table(TABLES["lab_tests"]).select("*")
    if status:
        query = query.eq("status", status)
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    
    result = query.order("request_date", desc=True).execute()
    tests = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for t in tests:
        t["patient_name"] = patient_map.get(t.get("patient_id"), "Inconnu")
    
    return jsonify(tests)

@app.route("/api/laboratory/tests", methods=["POST"])
@roles_required("super_admin", "docteur", "laboratoire", "gynecologue", "pediatre")
def create_lab_test():
    data = fast_json()
    if not data.get("patient_id") or not data.get("test_type"):
        return jsonify({"error": "Patient et type d'analyse requis"}), 422
    
    test = {
        "patient_id": to_int(data.get("patient_id")),
        "test_type": data.get("test_type"),
        "notes": data.get("notes", ""),
        "status": "pending",
        "priority": normalize_status(data.get("priority", "normal"), ["normal", "urgent"], "normal"),
        "request_date": now_iso(),
        "requested_by": g.current_user["id"],
        "requested_by_name": g.current_user["name"],
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["lab_tests"]).insert(test).execute()
    add_audit("CREATE", "lab_test", f"Analyse #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/laboratory/tests/<int:test_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_lab_test(test_id: int):
    result = supabase.table(TABLES["lab_tests"]).select("*").eq("id", test_id).execute()
    if not result.data:
        return jsonify({"error": "Analyse introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/laboratory/tests/<int:test_id>", methods=["PUT"])
@roles_required("super_admin", "laboratoire")
def update_lab_test(test_id: int):
    data = fast_json()
    allowed = ["test_type", "notes", "priority"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    updates["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["lab_tests"]).update(updates).eq("id", test_id).execute()
    if not result.data:
        return jsonify({"error": "Analyse introuvable"}), 404
    add_audit("UPDATE", "lab_test", f"Analyse #{test_id} modifiée", test_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/laboratory/tests/<int:test_id>/result", methods=["PUT"])
@roles_required("super_admin", "laboratoire")
def save_test_result(test_id: int):
    data = fast_json()
    updates = {
        "result": data.get("result", ""),
        "observations": data.get("observations", ""),
        "status": "completed",
        "completed_date": now_iso(),
        "technician_name": g.current_user["name"],
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["lab_tests"]).update(updates).eq("id", test_id).execute()
    if not result.data:
        return jsonify({"error": "Analyse introuvable"}), 404
    add_audit("UPDATE", "lab_test", f"Résultat ajouté analyse #{test_id}", test_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/laboratory/tests/<int:test_id>/result", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_test_result(test_id: int):
    result = supabase.table(TABLES["lab_tests"]).select("*").eq("id", test_id).execute()
    if not result.data:
        return jsonify({"error": "Analyse introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/laboratory/results", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(120)
def get_lab_results():
    date_from = request.args.get("from_date")
    date_to = request.args.get("to_date")
    
    query = supabase.table(TABLES["lab_tests"]).select("*").eq("status", "completed")
    if date_from:
        query = query.gte("completed_date", date_from)
    if date_to:
        query = query.lte("completed_date", date_to)
    
    result = query.order("completed_date", desc=True).execute()
    tests = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for t in tests:
        t["patient_name"] = patient_map.get(t.get("patient_id"), "Inconnu")
    
    return jsonify(tests)

@app.route("/api/laboratory/tests/<int:test_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_lab_test(test_id: int):
    supabase.table(TABLES["lab_tests"]).delete().eq("id", test_id).execute()
    add_audit("DELETE", "lab_test", f"Analyse #{test_id} supprimée", test_id)
    invalidate_cache()
    return jsonify({"message": "Analyse supprimée"})


# ==================== CARE LOGS ====================
@app.route("/api/care", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_care_logs():
    result = supabase.table(TABLES["care"]).select("*").order("date", desc=True).execute()
    care_logs = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for c in care_logs:
        c["patient_name"] = patient_map.get(c.get("patient_id"), "Inconnu")
    
    return jsonify(care_logs)

@app.route("/api/care", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "sage_femme")
def create_care_log():
    data = fast_json()
    if not data.get("patient_id") or not data.get("care_type"):
        return jsonify({"error": "Patient et type de soin requis"}), 422
    
    care = {
        "patient_id": to_int(data.get("patient_id")),
        "care_type": data.get("care_type"),
        "description": data.get("description", ""),
        "date": now_iso(),
        "performed_by": g.current_user["id"],
        "performed_by_name": g.current_user["name"],
        "created_at": now_iso(), 
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["care"]).insert(care).execute()
    add_audit("CREATE", "care", f"Soin #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/care/<int:care_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "sage_femme")
def update_care_log(care_id: int):
    data = fast_json()
    updates = {}
    if "care_type" in data:
        updates["care_type"] = data["care_type"]
    if "description" in data:
        updates["description"] = data["description"]
    updates["updated_at"] = now_iso()
    
    result = supabase.table(TABLES["care"]).update(updates).eq("id", care_id).execute()
    if not result.data:
        return jsonify({"error": "Soin introuvable"}), 404
    add_audit("UPDATE", "care", f"Soin #{care_id} modifié", care_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/care/<int:care_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_care_log(care_id: int):
    supabase.table(TABLES["care"]).delete().eq("id", care_id).execute()
    add_audit("DELETE", "care", f"Soin #{care_id} supprimé", care_id)
    invalidate_cache()
    return jsonify({"message": "Soin supprimé"})


# ==================== PHARMACY ====================
@app.route("/api/pharmacy", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_pharmacy():
    low_stock = request.args.get("low_stock", "false").lower() == "true"
    
    result = supabase.table(TABLES["pharmacy"]).select("*").order("medication_name").execute()
    items = result.data
    
    if low_stock:
        items = [i for i in items if i.get("quantity", 0) <= i.get("threshold", 10)]
    
    return jsonify(items)

@app.route("/api/pharmacy", methods=["POST"])
@roles_required("super_admin", "pharmacie")
def create_ph
