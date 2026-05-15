from __future__ import annotations

import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any
import urllib.error
import urllib.request

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_caching import Cache
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

# ==================== CONFIGURATION ====================
# ✅ CORRECTION: Utiliser les variables d'environnement avec fallback sécurisé
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://figmeixteescztmmprmi.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-[...]")
SECRET_KEY = os.getenv("SECRET_KEY", "ihub_super_secret_key_2024")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")  # ✅ CORRECTION: Pas de tuple, string simple
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")  # ✅ CORRECTION: Pas de tuple
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 10000))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
TOKEN_EXPIRY = 86400 * 7
CACHE_TIMEOUT = 300

# ==================== INITIALISATION ====================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = CACHE_TIMEOUT

cache = Cache(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

if not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY est requis")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

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
    "public": ["docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre"],
    "staff": ["super_admin", "docteur", "infirmier", "laboratoire", "pharmacie", "reception", "sage_femme", "gynecologue", "pediatre"],
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


def optional_date(value):
    return value or None


def missing_schema_column(exc: Exception) -> str | None:
    match = re.search(r"Could not find the '([^']+)' column", str(exc))
    return match.group(1) if match else None


def compatible_insert(table_name: str, data: dict):
    payload = dict(data)
    removed_columns = []
    while True:
        try:
            result = supabase.table(table_name).insert(payload).execute()
            if removed_columns:
                print(f"⚠️ Colonnes ignorees pour {table_name}: {', '.join(removed_columns)}")
            return result
        except Exception as exc:
            column = missing_schema_column(exc)
            if not column or column not in payload:
                raise
            removed_columns.append(column)
            payload.pop(column, None)


def invalidate_cache(pattern: str = None):
    cache.clear()


def cached(timeout=CACHE_TIMEOUT, key_prefix=None):
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



def parse_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except Exception:
        return None


def age_years(patient: dict):
    birth = parse_date(patient.get("date_of_birth") or patient.get("birth_date") or patient.get("dob"))
    if not birth:
        return None
    today = datetime.now(timezone.utc).date()
    return today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))


def is_female(patient: dict) -> bool:
    return str(patient.get("gender", "")).lower() in ("f", "female", "feminin", "féminin", "femme")


def active_pregnant_patient_ids() -> set:
    try:
        result = supabase.table("pregnancies").select("patient_id,status").eq("status", "active").execute()
        return {str(row.get("patient_id")) for row in (result.data or []) if row.get("patient_id")}
    except Exception:
        return set()


def filter_patients_for_role(patients: list) -> list:
    role = g.current_user.get("role") if hasattr(g, "current_user") else ""
    if role == "pediatre":
        return [p for p in patients if age_years(p) is not None and age_years(p) < 18]
    if role == "gynecologue":
        return [p for p in patients if is_female(p)]
    if role == "sage_femme":
        pregnant_ids = active_pregnant_patient_ids()
        return [p for p in patients if is_female(p) and str(p.get("id")) in pregnant_ids]
    return patients


def filter_appointments_for_role(appointments: list) -> list:
    role = g.current_user.get("role") if hasattr(g, "current_user") else ""
    if role != "gynecologue":
        return appointments
    user_id = str(g.current_user.get("id", ""))
    user_name = str(g.current_user.get("name", "")).lower()
    id_fields = ("doctor_id", "practitioner_id", "provider_id", "user_id", "created_by", "assigned_to")
    name_fields = ("doctor_name", "practitioner_name", "provider_name", "user_name")
    filtered = []
    for apt in appointments:
        if user_id and any(str(apt.get(field, "")) == user_id for field in id_fields):
            filtered.append(apt)
        elif user_name and any(str(apt.get(field, "")).lower() == user_name for field in name_fields):
            filtered.append(apt)
    return filtered

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
    try:
        compatible_insert(TABLES["audit"], {
            "action": action,
            "entity_type": entity,
            "entity_id": entity_id,
            "user_id": g.current_user.get("id") if hasattr(g, 'current_user') else None,
            "user_name": g.current_user.get("name") if hasattr(g, 'current_user') else "Systeme",
            "details": details or "",
            "created_at": now_iso()
        })
    except:
        pass


# ==================== AUTH ROUTES ====================
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
def get_patients():
    search = request.args.get("search", "").strip().lower()
    context = request.args.get("context", "").strip().lower()

    if search:
        result = supabase.table(TABLES["patients"]).select("*")\
            .or_(f"full_name.ilike.%{search}%,phone.ilike.%{search}%,email.ilike.%{search}%")\
            .order("created_at", desc=True).execute()
    else:
        result = supabase.table(TABLES["patients"]).select("*").order("created_at", desc=True).execute()

    patients = result.data or []
    if context in ("maternity", "pregnancy", "prenatal", "delivery") and g.current_user.get("role") in ("super_admin", "sage_femme", "gynecologue"):
        return jsonify([patient for patient in patients if is_female(patient)])

    return jsonify(filter_patients_for_role(patients))


@app.route("/api/patients", methods=["POST"])
@roles_required("super_admin", "reception")
def create_patient():
    data = fast_json()
    full_name = data.get("full_name", "").strip()
    if not full_name:
        return jsonify({"error": "Nom requis"}), 422

    patient = {
        "full_name": full_name,
        "phone": data.get("phone", ""),
        "email": data.get("email", ""),
        "date_of_birth": optional_date(data.get("date_of_birth")),
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
    result = compatible_insert(TABLES["patients"], patient)
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
    appointments = filter_appointments_for_role(result.data or [])

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
    result = compatible_insert(TABLES["appointments"], appointment)
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
@roles_required("super_admin", "docteur", "infirmier", "reception", "gynecologue", "pediatre")
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
        "start_date": optional_date(data.get("start_date")),
        "end_date": optional_date(data.get("end_date")),
        "instructions": data.get("instructions", ""),
        "status": data.get("status", "active"),
        "doctor_id": g.current_user["id"],
        "doctor_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    result = compatible_insert(TABLES["prescriptions"], prescription)
    add_audit("CREATE", "prescription", f"Prescription #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/prescriptions/<int:prescription_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "gynecologue", "pediatre")
def update_prescription(prescription_id: int):
    data = fast_json()
    allowed = ["medication", "dosage", "frequency", "duration", "start_date", "end_date", "instructions", "status"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    for date_field in ("start_date", "end_date"):
        if date_field in updates:
            updates[date_field] = optional_date(updates[date_field])
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
    result = compatible_insert(TABLES["lab_tests"], test)
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
    result = compatible_insert(TABLES["care"], care)
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
def create_pharmacy_item():
    data = fast_json()
    if not data.get("medication_name"):
        return jsonify({"error": "Nom du médicament requis"}), 422

    item = {
        "medication_name": data["medication_name"],
        "quantity": max(0, to_int(data.get("quantity"), 0)),
        "unit": data.get("unit", "comprimé(s)"),
        "purchase_price": max(0, to_float(data.get("purchase_price"), 0)),
        "selling_price": max(0, to_float(data.get("selling_price"), 0)),
        "threshold": max(0, to_int(data.get("threshold"), 10)),
        "expiry_date": optional_date(data.get("expiry_date")),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    result = compatible_insert(TABLES["pharmacy"], item)
    add_audit("CREATE", "pharmacy", f"Médicament: {data['medication_name']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/pharmacy/<int:item_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_pharmacy_item(item_id: int):
    result = supabase.table(TABLES["pharmacy"]).select("*").eq("id", item_id).execute()
    if not result.data:
        return jsonify({"error": "Médicament introuvable"}), 404
    return jsonify(result.data[0])


@app.route("/api/pharmacy/<int:item_id>", methods=["PUT"])
@roles_required("super_admin", "pharmacie")
def update_pharmacy_item(item_id: int):
    data = fast_json()
    allowed = ["medication_name", "unit", "purchase_price", "selling_price", "threshold", "expiry_date"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    if "expiry_date" in updates:
        updates["expiry_date"] = optional_date(updates["expiry_date"])
    updates["updated_at"] = now_iso()

    result = supabase.table(TABLES["pharmacy"]).update(updates).eq("id", item_id).execute()
    if not result.data:
        return jsonify({"error": "Médicament introuvable"}), 404
    add_audit("UPDATE", "pharmacy", f"Médicament #{item_id} modifié", item_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/pharmacy/<int:item_id>/stock", methods=["PUT"])
@roles_required("super_admin", "pharmacie")
def update_stock(item_id: int):
    data = fast_json()
    quantity = max(0, to_int(data.get("quantity"), 0))
    operation = data.get("operation", "set")

    item_result = supabase.table(TABLES["pharmacy"]).select("quantity").eq("id", item_id).execute()
    if not item_result.data:
        return jsonify({"error": "Médicament introuvable"}), 404

    current = to_int(item_result.data[0].get("quantity"), 0)
    if operation == "add":
        new_qty = current + quantity
    elif operation == "remove":
        if quantity > current:
            return jsonify({"error": "Stock insuffisant"}), 422
        new_qty = current - quantity
    else:
        new_qty = quantity

    result = supabase.table(TABLES["pharmacy"]).update({"quantity": new_qty, "updated_at": now_iso()}).eq("id", item_id).execute()
    add_audit("UPDATE", "pharmacy", f"Stock #{item_id}: {current} -> {new_qty}", item_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/pharmacy/<int:item_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_pharmacy_item(item_id: int):
    supabase.table(TABLES["pharmacy"]).delete().eq("id", item_id).execute()
    add_audit("DELETE", "pharmacy", f"Médicament #{item_id} supprimé", item_id)
    invalidate_cache()
    return jsonify({"message": "Médicament supprimé"})


# ==================== BILLING ====================
@app.route("/api/billing", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_invoices():
    status = request.args.get("status")
    patient_id = request.args.get("patient_id")

    query = supabase.table(TABLES["billing"]).select("*")
    if status:
        query = query.eq("status", status)
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))

    result = query.order("created_at", desc=True).execute()
    invoices = result.data

    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for inv in invoices:
        inv["patient_name"] = patient_map.get(inv.get("patient_id"), "Inconnu")

    return jsonify(invoices)


@app.route("/api/billing", methods=["POST"])
@roles_required("super_admin", "reception")
def create_invoice():
    data = fast_json()
    if not data.get("patient_id"):
        return jsonify({"error": "Patient requis"}), 422

    line_items = data.get("line_items") or data.get("items") or []

    calculated_amount = 0
    for item in line_items:
        qty = to_int(item.get("quantity"), 0)
        price = to_float(item.get("unit_price") or item.get("price"), 0)
        calculated_amount += qty * price

    amount = round(calculated_amount if calculated_amount > 0 else to_float(data.get("amount"), 0), 2)

    if amount <= 0:
        return jsonify({"error": "Montant invalide"}), 422

    invoice = {
        "invoice_number": f"FAC-{int(time.time())}-{secrets.token_hex(2).upper()}",
        "patient_id": to_int(data.get("patient_id")),
        "amount": amount,
        "description": data.get("description", ""),
        "status": "unpaid",
        "line_items": line_items,
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    result = compatible_insert(TABLES["billing"], invoice)
    add_audit("CREATE", "billing", f"Facture #{result.data[0]['id']}: {amount}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201



@app.route("/api/billing/grouped", methods=["POST"])
@roles_required("super_admin", "pharmacie", "reception")
def create_grouped_invoice():
    data = fast_json()
    items = data.get("items") or data.get("line_items") or []
    if not data.get("patient_id"):
        return jsonify({"error": "Patient requis"}), 422
    if not items:
        return jsonify({"error": "Aucun article à facturer"}), 422

    normalized_items = []
    total = 0.0
    for item in items:
        qty = max(1, to_int(item.get("quantity"), 1))
        unit_price = max(0, to_float(item.get("unit_price") or item.get("price"), 0))
        amount = round(to_float(item.get("amount"), qty * unit_price), 2)
        total += amount
        normalized_items.append({
            "medication_id": item.get("medication_id"),
            "code": item.get("code", ""),
            "description": item.get("description", ""),
            "quantity": qty,
            "unit_price": unit_price,
            "amount": amount
        })

    if total <= 0:
        return jsonify({"error": "Montant invalide"}), 422

    invoice = {
        "invoice_number": f"FAC-{int(time.time())}-{secrets.token_hex(2).upper()}",
        "patient_id": to_int(data.get("patient_id")),
        "amount": round(total, 2),
        "description": data.get("description", "Facture groupée"),
        "status": "unpaid",
        "line_items": normalized_items,
        "items": normalized_items,
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    result = compatible_insert(TABLES["billing"], invoice)

    if data.get("source") == "pharmacy":
        for item in normalized_items:
            med_id = to_int(item.get("medication_id"), 0)
            qty = to_int(item.get("quantity"), 0)
            if not med_id or not qty:
                continue
            current = supabase.table(TABLES["pharmacy"]).select("quantity").eq("id", med_id).execute()
            if current.data:
                new_qty = max(0, to_int(current.data[0].get("quantity"), 0) - qty)
                supabase.table(TABLES["pharmacy"]).update({"quantity": new_qty, "updated_at": now_iso()}).eq("id", med_id).execute()

    add_audit("CREATE", "billing", f"Facture groupée: {round(total, 2)}", result.data[0]["id"])
    invalidate_cache()
    return jsonify({"invoice": result.data[0]}), 201

@app.route("/api/billing/<int:invoice_id>", methods=["GET"])
@roles_required(*ROLES["staff"])
def get_invoice(invoice_id: int):
    result = supabase.table(TABLES["billing"]).select("*").eq("id", invoice_id).execute()
    if not result.data:
        return jsonify({"error": "Facture introuvable"}), 404
    return jsonify(result.data[0])


@app.route("/api/billing/<int:invoice_id>", methods=["PUT"])
@roles_required("super_admin", "reception")
def update_invoice(invoice_id: int):
    data = fast_json()
    allowed = ["amount", "description", "status"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    if "status" in updates:
        updates["status"] = "paid" if updates["status"] == "paid" else "unpaid"
        if updates["status"] == "paid":
            updates["paid_at"] = now_iso()
            updates["paid_by_user_id"] = g.current_user["id"]
            updates["paid_by_name"] = g.current_user["name"]
    updates["updated_at"] = now_iso()

    result = supabase.table(TABLES["billing"]).update(updates).eq("id", invoice_id).execute()
    if not result.data:
        return jsonify({"error": "Facture introuvable"}), 404
    add_audit("UPDATE", "billing", f"Facture #{invoice_id} modifiée", invoice_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/billing/<int:invoice_id>/pay", methods=["PUT"])
@roles_required("super_admin", "reception")
def mark_invoice_paid(invoice_id: int):
    updates = {
        "status": "paid",
        "paid_at": now_iso(),
        "paid_by_user_id": g.current_user["id"],
        "paid_by_name": g.current_user["name"],
        "updated_at": now_iso()
    }
    result = supabase.table(TABLES["billing"]).update(updates).eq("id", invoice_id).execute()
    if not result.data:
        return jsonify({"error": "Facture introuvable"}), 404
    add_audit("UPDATE", "billing", f"Facture #{invoice_id} payée", invoice_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/billing/<int:invoice_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_invoice(invoice_id: int):
    supabase.table(TABLES["billing"]).delete().eq("id", invoice_id).execute()
    add_audit("DELETE", "billing", f"Facture #{invoice_id} supprim��e", invoice_id)
    invalidate_cache()
    return jsonify({"message": "Facture supprimée"})


# ==================== USERS ====================
@app.route("/api/users", methods=["GET"])
@app.route("/api/auth/users", methods=["GET"])
@roles_required("super_admin")
@cached(120)
def get_users():
    result = supabase.table(TABLES["users"]).select("*").order("created_at", desc=True).execute()
    users = [{k: v for k, v in u.items() if k != "password_hash"} for u in result.data]
    return jsonify(users)


@app.route("/api/users", methods=["POST"])
@app.route("/api/auth/users", methods=["POST"])
@roles_required("super_admin")
def create_user():
    data = fast_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    role = data.get("role", "")

    if len(name) < 2:
        return jsonify({"error": "Nom trop court"}), 422
    if "@" not in email:
        return jsonify({"error": "Email invalide"}), 422
    if len(password) < 8:
        return jsonify({"error": "Mot de passe trop court"}), 422
    if role not in ROLES["staff"]:
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
    add_audit("CREATE", "user", f"Compte: {email}", result.data[0]["id"])
    invalidate_cache()
    return jsonify({k: v for k, v in result.data[0].items() if k != "password_hash"}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@app.route("/api/auth/users/<int:user_id>", methods=["PUT"])
@roles_required("super_admin")
def update_user(user_id: int):
    data = fast_json()
    updates = {}

    if "name" in data:
        updates["name"] = data["name"].strip()
    if "email" in data:
        updates["email"] = data["email"].lower().strip()
    if "role" in data and data["role"] in ROLES["staff"]:
        updates["role"] = data["role"]
    if "is_active" in data:
        updates["is_active"] = bool(data["is_active"])
    if "password" in data and data["password"]:
        if len(data["password"]) >= 8:
            updates["password_hash"] = generate_password_hash(data["password"])

    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour"}), 422

    updates["updated_at"] = now_iso()
    result = supabase.table(TABLES["users"]).update(updates).eq("id", user_id).execute()
    if not result.data:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    add_audit("UPDATE", "user", f"Compte #{user_id} modifié", user_id)
    invalidate_cache()
    return jsonify({k: v for k, v in result.data[0].items() if k != "password_hash"})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@app.route("/api/auth/users/<int:user_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_user(user_id: int):
    if user_id == g.current_user.get("id"):
        return jsonify({"error": "Vous ne pouvez pas supprimer votre propre compte"}), 422

    supabase.table(TABLES["users"]).delete().eq("id", user_id).execute()
    add_audit("DELETE", "user", f"Compte #{user_id} supprimé", user_id)
    invalidate_cache()
    return jsonify({"message": "Compte supprimé"})


# ==================== AUDIT ====================
@app.route("/api/audit", methods=["GET"])
@roles_required("super_admin")
@cached(120)
def get_audit_logs():
    action = request.args.get("action")
    entity = request.args.get("entity_type")
    user_id = request.args.get("user_id")
    limit = to_int(request.args.get("limit"), 500)

    query = supabase.table(TABLES["audit"]).select("*")
    if action:
        query = query.eq("action", action)
    if entity:
        query = query.eq("entity_type", entity)
    if user_id:
        query = query.eq("user_id", to_int(user_id))

    result = query.order("created_at", desc=True).limit(min(limit, 1000)).execute()
    return jsonify(result.data)


# ==================== HEALTH ====================
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "timestamp": now_iso(),
        "version": "2.0.0"
    })


# ==================== SEED ====================
def seed_admin():
    existing = supabase.table(TABLES["users"]).select("id").eq("email", "jeremyodimba322@gmail.com").execute()
    if not existing.data:
        supabase.table(TABLES["users"]).insert({
            "name": "Administrateur",
            "email": "jeremyodimba322@gmail.com",
            "password_hash": generate_password_hash("admin123"),
            "role": "super_admin",
            "is_active": True,
            "created_at": now_iso(),
            "updated_at": now_iso()
        }).execute()
        print("✅ Super admin créé (email: jeremyodimba322@gmail.com, mot de passe: admin123)")


# ==================== INITIALISATION DES TABLES ====================
def execute_schema_sql(sql: str, label: str):
    if not hasattr(supabase, "sql"):
        print(f"⚠️ Table {label} absente. Créez-la dans Supabase SQL Editor avec le schéma prévu.")
        return
    try:
        supabase.sql(sql).execute()
        print(f"✅ Table {label} créée")
    except Exception as exc:
        print(f"⚠️ Création table {label} impossible: {exc}")


def init_maternity_tables():
    """Crée les tables pour le module maternité si elles n'existent pas"""
    
    # Table pregnancies
    try:
        supabase.table("pregnancies").select("id").limit(1).execute()
        print("✅ Table pregnancies existe déjà")
    except Exception:
        execute_schema_sql("""
                CREATE TABLE IF NOT EXISTS pregnancies (
                    id SERIAL PRIMARY KEY,
                    patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
                    last_menstrual_period DATE NOT NULL,
                    expected_delivery_date DATE,
                    blood_type VARCHAR(10),
                    risk_level VARCHAR(20) DEFAULT 'normal',
                    medical_history TEXT,
                    status VARCHAR(20) DEFAULT 'active',
                    created_by INTEGER,
                    created_by_name VARCHAR(100),
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
        """, "pregnancies")
    
    # Table prenatal_consultations
    try:
        supabase.table("prenatal_consultations").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS prenatal_consultations (
                id SERIAL PRIMARY KEY,
                patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
                pregnancy_id INTEGER REFERENCES pregnancies(id) ON DELETE CASCADE,
                visit_date DATE NOT NULL,
                gestational_weeks VARCHAR(10),
                weight DECIMAL(5,2),
                blood_pressure VARCHAR(20),
                fetal_heartbeat VARCHAR(50),
                observations TEXT,
                created_by INTEGER,
                created_by_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "prenatal_consultations")
    
    # Table deliveries
    try:
        supabase.table("deliveries").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS deliveries (
                id SERIAL PRIMARY KEY,
                patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
                pregnancy_id INTEGER REFERENCES pregnancies(id) ON DELETE SET NULL,
                delivery_date DATE NOT NULL,
                delivery_type VARCHAR(30) DEFAULT 'vaginal',
                baby_count INTEGER DEFAULT 1,
                babies JSONB,
                observations TEXT,
                status VARCHAR(20) DEFAULT 'completed',
                delivered_by INTEGER,
                delivered_by_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "deliveries")
    
    # Table maternity_rooms
    try:
        supabase.table("maternity_rooms").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS maternity_rooms (
                id SERIAL PRIMARY KEY,
                room_number VARCHAR(20) UNIQUE NOT NULL,
                type VARCHAR(50) DEFAULT 'Standard',
                status VARCHAR(20) DEFAULT 'available',
                patient_id INTEGER REFERENCES patients(id) ON DELETE SET NULL,
                admission_date TIMESTAMP,
                discharge_date TIMESTAMP,
                admission_reason TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "maternity_rooms")
    
    # Table children
    try:
        supabase.table("children").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS children (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                date_of_birth DATE NOT NULL,
                gender CHAR(1) DEFAULT 'M',
                parent_id INTEGER REFERENCES patients(id) ON DELETE SET NULL,
                blood_type VARCHAR(10),
                allergies TEXT,
                medical_history TEXT,
                vaccination_status VARCHAR(20) DEFAULT 'pending',
                birth_weight INTEGER,
                birth_height INTEGER,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "children")
    
    # Table vaccinations
    try:
        supabase.table("vaccinations").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS vaccinations (
                id SERIAL PRIMARY KEY,
                child_id INTEGER REFERENCES children(id) ON DELETE CASCADE,
                vaccine_name VARCHAR(100) NOT NULL,
                administered_date DATE NOT NULL,
                dose_number INTEGER DEFAULT 1,
                next_due_date DATE,
                batch_number VARCHAR(50),
                notes TEXT,
                administered_by INTEGER,
                administered_by_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "vaccinations")
    
    # Table growth_measurements
    try:
        supabase.table("growth_measurements").select("id").limit(1).execute()
    except:
        execute_schema_sql("""
            CREATE TABLE IF NOT EXISTS growth_measurements (
                id SERIAL PRIMARY KEY,
                child_id INTEGER REFERENCES children(id) ON DELETE CASCADE,
                measurement_date DATE NOT NULL,
                weight DECIMAL(5,2),
                height DECIMAL(5,2),
                head_circumference DECIMAL(5,2),
                percentile INTEGER,
                notes TEXT,
                created_by INTEGER,
                created_by_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """, "growth_measurements")


# ==================== MATERNITÉ ROUTES ====================

@app.route("/api/maternity/pregnancies", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
@cached(60)
def get_pregnancies():
    patient_id = request.args.get("patient_id")
    status = request.args.get("status", "active")
    
    query = supabase.table("pregnancies").select("*")
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if status:
        query = query.eq("status", status)
    
    result = query.order("created_at", desc=True).execute()
    pregnancies = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for p in pregnancies:
        p["patient_name"] = patient_map.get(p.get("patient_id"), "Inconnu")
    
    return jsonify(pregnancies)


@app.route("/api/maternity/pregnancies", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_pregnancy():
    data = fast_json()
    
    if not data.get("patient_id") or not data.get("last_menstrual_period"):
        return jsonify({"error": "Patient et DDR requis"}), 422
    
    pregnancy = {
        "patient_id": to_int(data.get("patient_id")),
        "last_menstrual_period": data.get("last_menstrual_period"),
        "expected_delivery_date": data.get("expected_delivery_date"),
        "blood_type": data.get("blood_type", ""),
        "risk_level": data.get("risk_level", "normal"),
        "medical_history": data.get("medical_history", ""),
        "status": data.get("status", "active"),
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("pregnancies", pregnancy)
    add_audit("CREATE", "pregnancy", f"Grossesse #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/maternity/pregnancies/<int:pregnancy_id>", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def get_pregnancy(pregnancy_id: int):
    result = supabase.table("pregnancies").select("*").eq("id", pregnancy_id).execute()
    if not result.data:
        return jsonify({"error": "Grossesse introuvable"}), 404
    
    pregnancy = result.data[0]
    patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", pregnancy["patient_id"]).execute()
    if patient.data:
        pregnancy["patient_name"] = patient.data[0]["full_name"]
    
    return jsonify(pregnancy)



@app.route("/api/maternity/pregnancies/<int:pregnancy_id>", methods=["PUT"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def update_pregnancy(pregnancy_id: int):
    data = fast_json()
    allowed = [
        "last_menstrual_period", "expected_delivery_date", "blood_type",
        "risk_level", "medical_history", "status", "notes"
    ]
    updates = {key: value for key, value in data.items() if key in allowed and value is not None}
    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour"}), 422
    updates["updated_at"] = now_iso()
    result = supabase.table("pregnancies").update(updates).eq("id", pregnancy_id).execute()
    if not result.data:
        return jsonify({"error": "Grossesse introuvable"}), 404
    add_audit("UPDATE", "pregnancy", f"Grossesse #{pregnancy_id} modifiée", pregnancy_id)
    invalidate_cache()
    return jsonify(result.data[0])

@app.route("/api/maternity/pregnancies/<int:pregnancy_id>/followups", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def get_pregnancy_followups(pregnancy_id: int):
    result = supabase.table("prenatal_consultations").select("*").eq("pregnancy_id", pregnancy_id).order("visit_date", desc=True).execute()
    return jsonify(result.data)


@app.route("/api/maternity/prenatal", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
@cached(60)
def get_prenatal_consultations():
    patient_id = request.args.get("patient_id")
    pregnancy_id = request.args.get("pregnancy_id")
    
    query = supabase.table("prenatal_consultations").select("*")
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    if pregnancy_id:
        query = query.eq("pregnancy_id", to_int(pregnancy_id))
    
    result = query.order("visit_date", desc=True).execute()
    consultations = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for c in consultations:
        c["patient_name"] = patient_map.get(c.get("patient_id"), "Inconnu")
    
    return jsonify(consultations)


@app.route("/api/maternity/prenatal", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_prenatal_consultation():
    data = fast_json()
    
    if not data.get("patient_id") or not data.get("visit_date"):
        return jsonify({"error": "Patient et date requis"}), 422
    
    consultation = {
        "patient_id": to_int(data.get("patient_id")),
        "pregnancy_id": data.get("pregnancy_id"),
        "visit_date": data.get("visit_date"),
        "weight": data.get("weight"),
        "blood_pressure": data.get("blood_pressure", ""),
        "fetal_heartbeat": data.get("fetal_heartbeat", ""),
        "observations": data.get("observations", ""),
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("prenatal_consultations", consultation)
    add_audit("CREATE", "prenatal", f"Consultation prénatale #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/maternity/prenatal/<int:consultation_id>", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def get_prenatal_consultation(consultation_id: int):
    result = supabase.table("prenatal_consultations").select("*").eq("id", consultation_id).execute()
    if not result.data:
        return jsonify({"error": "Consultation introuvable"}), 404
    return jsonify(result.data[0])


@app.route("/api/maternity/deliveries", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
@cached(60)
def get_deliveries():
    patient_id = request.args.get("patient_id")
    
    query = supabase.table("deliveries").select("*")
    if patient_id:
        query = query.eq("patient_id", to_int(patient_id))
    
    result = query.order("delivery_date", desc=True).execute()
    deliveries = result.data
    
    patients_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients_result.data}
    for d in deliveries:
        d["patient_name"] = patient_map.get(d.get("patient_id"), "Inconnu")
        if d.get("babies"):
            d["babies"] = json.loads(d["babies"]) if isinstance(d["babies"], str) else d["babies"]
    
    return jsonify(deliveries)


@app.route("/api/maternity/deliveries", methods=["POST"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def create_delivery():
    data = fast_json()
    
    if not data.get("patient_id") or not data.get("delivery_date"):
        return jsonify({"error": "Patient et date requis"}), 422
    
    pregnancy_id = data.get("pregnancy_id")
    if pregnancy_id:
        supabase.table("pregnancies").update({"status": "completed", "updated_at": now_iso()}).eq("id", pregnancy_id).execute()
    
    delivery = {
        "patient_id": to_int(data.get("patient_id")),
        "pregnancy_id": pregnancy_id,
        "delivery_date": data.get("delivery_date"),
        "delivery_type": data.get("delivery_type", "vaginal"),
        "baby_count": data.get("baby_count", 1),
        "babies": json.dumps(data.get("babies", [])),
        "observations": data.get("observations", ""),
        "status": "completed",
        "delivered_by": g.current_user["id"],
        "delivered_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("deliveries", delivery)
    
    # Créer automatiquement des fiches enfants pour les nouveau-nés
    babies = data.get("babies", [])
    for idx, baby in enumerate(babies):
        child_data = {
            "full_name": f"Bébé de la patiente #{data.get('patient_id')}",
            "date_of_birth": data.get("delivery_date"),
            "gender": baby.get("gender", "M"),
            "parent_id": data.get("patient_id"),
            "blood_type": baby.get("blood_type", ""),
            "birth_weight": baby.get("weight"),
            "birth_height": baby.get("height"),
            "created_at": now_iso(),
            "updated_at": now_iso()
        }
        try:
            compatible_insert("children", child_data)
        except Exception as exc:
            print(f"⚠️ Fiche enfant non créée après accouchement: {exc}")
    
    add_audit("CREATE", "delivery", f"Accouchement #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/maternity/deliveries/<int:delivery_id>", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
def get_delivery(delivery_id: int):
    result = supabase.table("deliveries").select("*").eq("id", delivery_id).execute()
    if not result.data:
        return jsonify({"error": "Accouchement introuvable"}), 404
    
    delivery = result.data[0]
    patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", delivery["patient_id"]).execute()
    if patient.data:
        delivery["patient_name"] = patient.data[0]["full_name"]
    if delivery.get("babies"):
        delivery["babies"] = json.loads(delivery["babies"]) if isinstance(delivery["babies"], str) else delivery["babies"]
    
    return jsonify(delivery)


@app.route("/api/maternity/rooms", methods=["GET"])
@roles_required("super_admin", "sage_femme", "gynecologue")
@cached(60)
def get_maternity_rooms():
    result = supabase.table("maternity_rooms").select("*").order("room_number").execute()
    rooms = result.data
    
    for room in rooms:
        if room.get("patient_id") and room.get("status") == "occupied":
            patient = supabase.table(TABLES["patients"]).select("full_name").eq("id", room["patient_id"]).execute()
            if patient.data:
                room["patient_name"] = patient.data[0]["full_name"]
    
    return jsonify(rooms)


@app.route("/api/maternity/rooms", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def create_maternity_room():
    data = fast_json()
    
    if not data.get("room_number"):
        return jsonify({"error": "Numéro de lit requis"}), 422
    
    room = {
        "room_number": data.get("room_number"),
        "type": data.get("type", "Standard"),
        "status": "available",
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("maternity_rooms", room)
    add_audit("CREATE", "maternity_room", f"Lit #{result.data[0]['room_number']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/maternity/rooms/admit", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def admit_to_maternity():
    data = fast_json()
    
    if not data.get("room_id") or not data.get("patient_id"):
        return jsonify({"error": "Lit et patient requis"}), 422
    
    room = supabase.table("maternity_rooms").select("*").eq("id", data["room_id"]).execute()
    if not room.data:
        return jsonify({"error": "Lit introuvable"}), 404
    
    if room.data[0]["status"] != "available":
        return jsonify({"error": "Lit déjà occupé"}), 422
    
    updates = {
        "status": "occupied",
        "patient_id": to_int(data.get("patient_id")),
        "admission_date": now_iso(),
        "admission_reason": data.get("reason", ""),
        "updated_at": now_iso()
    }
    
    result = supabase.table("maternity_rooms").update(updates).eq("id", data["room_id"]).execute()
    add_audit("UPDATE", "maternity_room", f"Admission patient #{data['patient_id']} au lit #{room.data[0]['room_number']}", data["room_id"])
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/maternity/rooms/<int:room_id>/discharge", methods=["POST"])
@roles_required("super_admin", "sage_femme")
def discharge_from_maternity(room_id: int):
    updates = {
        "status": "available",
        "patient_id": None,
        "discharge_date": now_iso(),
        "admission_reason": None,
        "updated_at": now_iso()
    }
    
    result = supabase.table("maternity_rooms").update(updates).eq("id", room_id).execute()
    if not result.data:
        return jsonify({"error": "Lit introuvable"}), 404
    
    add_audit("UPDATE", "maternity_room", f"Libération du lit #{result.data[0]['room_number']}", room_id)
    invalidate_cache()
    return jsonify(result.data[0])


# ==================== PÉDIATRIE ROUTES ====================

@app.route("/api/pediatrics/children", methods=["GET"])
@roles_required("super_admin", "pediatre", "sage_femme")
@cached(60)
def get_children():
    parent_id = request.args.get("parent_id")
    
    query = supabase.table("children").select("*")
    if parent_id:
        query = query.eq("parent_id", to_int(parent_id))
    
    result = query.order("created_at", desc=True).execute()
    children = result.data
    
    parents_result = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    parent_map = {p["id"]: p["full_name"] for p in parents_result.data}
    for c in children:
        c["parent_name"] = parent_map.get(c.get("parent_id"), "Inconnu")
    
    return jsonify(children)


@app.route("/api/pediatrics/children", methods=["POST"])
@roles_required("super_admin", "pediatre", "sage_femme")
def create_child():
    data = fast_json()
    
    if not data.get("full_name") or not data.get("date_of_birth"):
        return jsonify({"error": "Nom et date de naissance requis"}), 422
    
    child = {
        "full_name": data.get("full_name"),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", "M"),
        "parent_id": data.get("parent_id"),
        "blood_type": data.get("blood_type", ""),
        "allergies": data.get("allergies", ""),
        "medical_history": data.get("medical_history", ""),
        "vaccination_status": "pending",
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("children", child)
    add_audit("CREATE", "child", f"Enfant #{result.data[0]['full_name']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/pediatrics/children/<int:child_id>", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_child(child_id: int):
    result = supabase.table("children").select("*").eq("id", child_id).execute()
    if not result.data:
        return jsonify({"error": "Enfant introuvable"}), 404
    
    child = result.data[0]
    if child.get("parent_id"):
        parent = supabase.table(TABLES["patients"]).select("full_name").eq("id", child["parent_id"]).execute()
        if parent.data:
            child["parent_name"] = parent.data[0]["full_name"]
    
    return jsonify(child)


@app.route("/api/pediatrics/children/<int:child_id>", methods=["PUT"])
@roles_required("super_admin", "pediatre")
def update_child(child_id: int):
    data = fast_json()
    allowed = ["full_name", "blood_type", "allergies", "medical_history", "vaccination_status"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    updates["updated_at"] = now_iso()
    
    result = supabase.table("children").update(updates).eq("id", child_id).execute()
    if not result.data:
        return jsonify({"error": "Enfant introuvable"}), 404
    
    add_audit("UPDATE", "child", f"Enfant #{child_id} modifié", child_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/pediatrics/vaccinations", methods=["GET"])
@roles_required("super_admin", "pediatre")
@cached(60)
def get_vaccinations():
    child_id = request.args.get("child_id")
    
    query = supabase.table("vaccinations").select("*")
    if child_id:
        query = query.eq("child_id", to_int(child_id))
    
    result = query.order("administered_date", desc=True).execute()
    vaccinations = result.data
    
    children_result = supabase.table("children").select("id", "full_name").execute()
    child_map = {c["id"]: c["full_name"] for c in children_result.data}
    for v in vaccinations:
        v["child_name"] = child_map.get(v.get("child_id"), "Inconnu")
    
    return jsonify(vaccinations)


@app.route("/api/pediatrics/vaccinations", methods=["POST"])
@roles_required("super_admin", "pediatre")
def create_vaccination():
    data = fast_json()
    
    if not data.get("child_id") or not data.get("vaccine_name") or not data.get("administered_date"):
        return jsonify({"error": "Enfant, vaccin et date requis"}), 422
    
    vaccination = {
        "child_id": to_int(data.get("child_id")),
        "vaccine_name": data.get("vaccine_name"),
        "administered_date": data.get("administered_date"),
        "dose_number": data.get("dose_number", 1),
        "next_due_date": data.get("next_due_date"),
        "batch_number": data.get("batch_number", ""),
        "notes": data.get("notes", ""),
        "administered_by": g.current_user["id"],
        "administered_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("vaccinations", vaccination)
    
    # Mettre à jour le statut vaccinal de l'enfant
    supabase.table("children").update({"vaccination_status": "up_to_date", "updated_at": now_iso()}).eq("id", data["child_id"]).execute()
    
    add_audit("CREATE", "vaccination", f"Vaccin #{data['vaccine_name']} pour enfant #{data['child_id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/pediatrics/vaccinations/<int:vaccination_id>", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_vaccination(vaccination_id: int):
    result = supabase.table("vaccinations").select("*").eq("id", vaccination_id).execute()
    if not result.data:
        return jsonify({"error": "Vaccination introuvable"}), 404
    return jsonify(result.data[0])


@app.route("/api/pediatrics/vaccinations/<int:vaccination_id>", methods=["PUT"])
@roles_required("super_admin", "pediatre")
def update_vaccination(vaccination_id: int):
    data = fast_json()
    allowed = ["next_due_date", "notes"]
    updates = {k: v for k, v in data.items() if k in allowed and v is not None}
    updates["updated_at"] = now_iso()
    
    result = supabase.table("vaccinations").update(updates).eq("id", vaccination_id).execute()
    if not result.data:
        return jsonify({"error": "Vaccination introuvable"}), 404
    
    add_audit("UPDATE", "vaccination", f"Vaccination #{vaccination_id} modifiée", vaccination_id)
    invalidate_cache()
    return jsonify(result.data[0])


@app.route("/api/pediatrics/children/<int:child_id>/vaccinations", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_child_vaccinations(child_id: int):
    result = supabase.table("vaccinations").select("*").eq("child_id", child_id).order("administered_date", desc=True).execute()
    return jsonify(result.data)


@app.route("/api/pediatrics/growth", methods=["GET"])
@roles_required("super_admin", "pediatre")
@cached(60)
def get_growth_measurements():
    child_id = request.args.get("child_id")
    
    query = supabase.table("growth_measurements").select("*")
    if child_id:
        query = query.eq("child_id", to_int(child_id))
    
    result = query.order("measurement_date", desc=True).execute()
    measurements = result.data
    
    children_result = supabase.table("children").select("id", "full_name").execute()
    child_map = {c["id"]: c["full_name"] for c in children_result.data}
    for m in measurements:
        m["child_name"] = child_map.get(m.get("child_id"), "Inconnu")
        if m.get("measurement_date"):
            child = supabase.table("children").select("date_of_birth").eq("id", m["child_id"]).execute()
            if child.data and child.data[0].get("date_of_birth"):
                birth = datetime.fromisoformat(child.data[0]["date_of_birth"])
                measure_date = datetime.fromisoformat(m["measurement_date"])
                months = (measure_date.year - birth.year) * 12 + (measure_date.month - birth.month)
                m["age_months"] = max(0, months)
    
    return jsonify(measurements)


@app.route("/api/pediatrics/growth", methods=["POST"])
@roles_required("super_admin", "pediatre")
def create_growth_measurement():
    data = fast_json()
    
    if not data.get("child_id") or not data.get("measurement_date"):
        return jsonify({"error": "Enfant et date requis"}), 422
    
    measurement = {
        "child_id": to_int(data.get("child_id")),
        "measurement_date": data.get("measurement_date"),
        "weight": data.get("weight"),
        "height": data.get("height"),
        "head_circumference": data.get("head_circumference"),
        "notes": data.get("notes", ""),
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    
    result = compatible_insert("growth_measurements", measurement)
    add_audit("CREATE", "growth", f"Mesure croissance pour enfant #{data['child_id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201


@app.route("/api/pediatrics/children/<int:child_id>/growth", methods=["GET"])
@roles_required("super_admin", "pediatre")
def get_child_growth(child_id: int):
    result = supabase.table("growth_measurements").select("*").eq("child_id", child_id).order("measurement_date", asc=True).execute()
    return jsonify(result.data)



# ==================== AI ROUTES ====================
AI_DISCLAIMER = "Assistant médical uniquement: validation clinique obligatoire par un professionnel habilité."


# ✅ CORRECTION: Fonction améliorée avec meilleure gestion d'erreur
def groq_chat(system_prompt: str, user_prompt: str) -> str:
    """Appelle l'API Groq avec gestion d'erreur robuste"""
    if not GROQ_API_KEY or not GROQ_API_KEY.startswith("gsk_"):
        return "❌ IA non configurée: GROQ_API_KEY manquant ou invalide côté serveur."
    
    try:
        payload = json.dumps({
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": f"{system_prompt}\n{AI_DISCLAIMER}"},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 900
        }).encode("utf-8")
        
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=25) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
    
    except urllib.error.HTTPError as e:
        try:
            error_body = json.loads(e.read().decode("utf-8"))
            return f"❌ Erreur API Groq: {error_body.get('error', {}).get('message', str(e))}"
        except:
            return f"❌ Erreur API Groq ({e.code}): {e.reason}"
    
    except Exception as exc:
        return f"❌ IA indisponible: {str(exc)}"


def ai_payload(key: str, value: str):
    return jsonify({key: value, "disclaimer": AI_DISCLAIMER})


@app.route("/api/ai/patient-summary", methods=["POST"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue", "pediatre")
def ai_patient_summary():
    data = fast_json()
    patient_id = to_int(data.get("patient_id"))
    patient_result = supabase.table(TABLES["patients"]).select("*").eq("id", patient_id).execute()
    if not patient_result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    patient = filter_patients_for_role(patient_result.data)
    if not patient:
        return jsonify({"error": "Accès patient interdit pour ce rôle"}), 403
    summary = groq_chat(
        "Résume un dossier patient de façon structurée et prudente, sans diagnostic final.",
        json.dumps(patient[0], ensure_ascii=False)
    )
    return ai_payload("summary", summary)


@app.route("/api/ai/clinical-decision", methods=["POST"])
@roles_required("super_admin", "docteur", "sage_femme", "gynecologue", "pediatre")
def ai_clinical_decision():
    context = fast_json().get("context", "")
    analysis = groq_chat(
        "Aide à l'orientation clinique. Donne priorités, signes d'alerte, examens utiles et limites. Ne pose pas de diagnostic final.",
        context
    )
    return ai_payload("analysis", analysis)


@app.route("/api/ai/hospital-flow", methods=["POST"])
@roles_required(*ROLES["staff"])
def ai_hospital_flow():
    data = fast_json()
    prediction = groq_chat(
        "Prédis l'affluence hospitalière à court terme et propose des recommandations opérationnelles.",
        json.dumps(data, ensure_ascii=False)[:12000]
    )
    return ai_payload("prediction", prediction)

# ==================== LANCEMENT ====================
if __name__ == "__main__":
    print("=" * 50)
    print("🏥 I HUB HOSPITAL API - VERSION COMPLÈTE")
    print("=" * 50)
    
    # ✅ Afficher le statut IA
    if GROQ_API_KEY and GROQ_API_KEY.startswith("gsk_"):
        print("✅ IA Groq: ACTIVÉE")
    else:
        print("⚠️ IA Groq: DÉSACTIVÉE (clé manquante/invalide)")
    
    seed_admin()
    init_maternity_tables()
    print(f"🚀 Serveur démarré sur http://{HOST}:{PORT}")
    print("=" * 50)
    app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)
