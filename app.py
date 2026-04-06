#!/usr/bin/env python3
"""
USHUDa Hospital API
Backend Flask securise avec stockage Supabase.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request
from flask_cors import CORS
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash

# ==================== CONFIGURATION DIRECTE (SANS .env) ====================
SUPABASE_URL = "https://figmeixteescztmmprmi.supabase.co"
SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-Bwv0EUQzME3nZR8ZPoSwTMCaybHRnw_-7Ew"
APP_SECRET = "super_secure_12345"
HOST = "0.0.0.0"
PORT = 5000
DEBUG = False
TOKEN_TTL_SECONDS = 604800
SUPER_ADMIN_NAME = "Administrateur"
SUPER_ADMIN_EMAIL = "jeremyodimba322@gmail.com"
SUPER_ADMIN_PASSWORD = "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"

# ==================== INITIALISATION ====================
app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET

# CORS corrigé pour Android - accepte TOUTES les origines
CORS(app, resources={r"/api/*": {"origins": "*"}})

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
token_serializer = URLSafeTimedSerializer(APP_SECRET, salt="ushuda-auth-token")

# ==================== NOMS DES TABLES ====================
USERS_TABLE = "app_users"
PATIENTS_TABLE = "patients"
APPOINTMENTS_TABLE = "appointments"
PRESCRIPTIONS_TABLE = "prescriptions"
LAB_TESTS_TABLE = "laboratory_tests"
CARE_LOGS_TABLE = "care_logs"
PHARMACY_TABLE = "pharmacy_items"
INVOICES_TABLE = "invoices"
AUDIT_TABLE = "audit_logs"

# ==================== RÔLES ET PERMISSIONS ====================
PUBLIC_REGISTRATION_ROLES = {"docteur", "infirmier", "laboratoire", "pharmacie", "reception"}
STAFF_ROLES = {"super_admin", *PUBLIC_REGISTRATION_ROLES}
PATIENT_READ_ROLES = STAFF_ROLES
PATIENT_WRITE_ROLES = {"super_admin", "docteur", "infirmier", "reception"}
APPOINTMENT_ROLES = {"super_admin", "docteur", "infirmier", "reception"}
PRESCRIPTION_READ_ROLES = {"super_admin", "docteur", "pharmacie"}
PRESCRIPTION_WRITE_ROLES = {"super_admin", "docteur"}
LAB_ROLES = {"super_admin", "docteur", "laboratoire"}
CARE_ROLES = {"super_admin", "docteur", "infirmier"}
PHARMACY_ROLES = {"super_admin", "pharmacie"}
BILLING_ROLES = {"super_admin", "reception"}
AUDIT_ROLES = {"super_admin"}

# ==================== FONCTIONS UTILITAIRES ====================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_json() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}

def error(message: str, status: int = 400):
    return jsonify({"error": message}), status

def normalize_priority(value: Any, default: str = "normal") -> str:
    value = str(value or default).strip().lower()
    return value if value in {"normal", "suivi", "urgent"} else default

def normalize_patient_status(value: Any, default: str = "active") -> str:
    value = str(value or default).strip().lower()
    return value if value in {"active", "admitted", "discharged"} else default

def normalize_appointment_status(value: Any, default: str = "scheduled") -> str:
    value = str(value or default).strip().lower()
    return value if value in {"scheduled", "completed", "cancelled"} else default

def normalize_invoice_status(value: Any, default: str = "unpaid") -> str:
    value = str(value or default).strip().lower()
    return value if value in {"unpaid", "paid"} else default

def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in user.items() if key != "password_hash"}

def build_line_items(description: str, amount: float, items: Any) -> list[dict[str, Any]]:
    if isinstance(items, list) and items:
        normalized = []
        for item in items:
            if not isinstance(item, dict):
                continue
            normalized.append(
                {
                    "label": str(item.get("label", "")).strip() or "Prestation",
                    "quantity": max(1, to_int(item.get("quantity", 1), 1)),
                    "unit_price": max(0.0, to_float(item.get("unit_price", amount))),
                    "total": max(0.0, to_float(item.get("total", amount))),
                }
            )
        if normalized:
            return normalized

    label = str(description or "").strip() or "Prestation hospitaliere"
    return [{"label": label, "quantity": 1, "unit_price": amount, "total": amount}]

def generate_invoice_number() -> str:
    return f"FAC-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"

# ==================== REQUÊTES SUPABASE ====================
def query_table(
    table: str,
    *,
    filters: dict[str, Any] | None = None,
    order: str | None = None,
    desc: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    query = supabase.table(table).select("*")
    for key, value in (filters or {}).items():
        query = query.eq(key, value)
    if order:
        query = query.order(order, desc=desc)
    if limit:
        query = query.limit(limit)
    response = query.execute()
    return list(response.data or [])

def get_one(table: str, record_id: int) -> dict[str, Any] | None:
    rows = query_table(table, filters={"id": record_id}, limit=1)
    return rows[0] if rows else None

def insert_row(table: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = supabase.table(table).insert(payload).execute()
    rows = list(response.data or [])
    if not rows:
        raise RuntimeError(f"Insertion impossible dans {table}.")
    return rows[0]

def update_row(table: str, record_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    payload["updated_at"] = now_iso()
    response = supabase.table(table).update(payload).eq("id", record_id).execute()
    rows = list(response.data or [])
    if not rows:
        raise RuntimeError(f"Mise a jour impossible dans {table}.")
    return rows[0]

def delete_row(table: str, record_id: int) -> None:
    supabase.table(table).delete().eq("id", record_id).execute()

def get_user_by_email(email: str) -> dict[str, Any] | None:
    rows = query_table(USERS_TABLE, filters={"email": email}, limit=1)
    return rows[0] if rows else None

def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    return get_one(USERS_TABLE, user_id)

def get_patient_by_id(patient_id: int) -> dict[str, Any] | None:
    return get_one(PATIENTS_TABLE, patient_id)

def get_patient_map() -> dict[int, dict[str, Any]]:
    return {patient["id"]: patient for patient in query_table(PATIENTS_TABLE)}

def enrich_patient_search(patient: dict[str, Any], search: str) -> bool:
    blob = " ".join(
        [
            str(patient.get("full_name", "")),
            str(patient.get("phone", "")),
            str(patient.get("email", "")),
            str(patient.get("blood_type", "")),
            str(patient.get("allergies", "")),
            str(patient.get("medical_history", "")),
            str(patient.get("insurance", "")),
            str(patient.get("emergency_contact", "")),
        ]
    ).lower()
    return search in blob

# ==================== AUTHENTIFICATION ====================
def create_token(user: dict[str, Any]) -> str:
    payload = {
        "sub": user["id"],
        "role": user["role"],
        "email": user["email"],
        "nonce": secrets.token_hex(8),
    }
    return token_serializer.dumps(payload)

def decode_token(token: str) -> dict[str, Any]:
    return token_serializer.loads(token, max_age=TOKEN_TTL_SECONDS)

def add_audit(action: str, entity_type: str, user: dict[str, Any] | None = None, details: str | None = None, entity_id: int | None = None) -> None:
    actor = user or {}
    payload = {
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user_id": actor.get("id"),
        "user_name": actor.get("name", "Systeme"),
        "details": details or "",
        "created_at": now_iso(),
    }
    insert_row(AUDIT_TABLE, payload)

# ==================== DÉCORATEURS ====================
def token_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error("Session expiree. Veuillez vous reconnecter.", 401)

        token = auth_header[7:].strip()
        if not token:
            return error("Token manquant.", 401)

        try:
            payload = decode_token(token)
        except SignatureExpired:
            return error("Session expiree. Veuillez vous reconnecter.", 401)
        except BadSignature:
            return error("Token invalide.", 401)

        user = get_user_by_id(to_int(payload.get("sub")))
        if not user or not user.get("is_active", True):
            return error("Utilisateur introuvable ou inactif.", 401)

        request.current_user = user
        return handler(*args, **kwargs)

    return wrapped

def roles_required(*allowed_roles: str):
    allowed = set(allowed_roles)

    def decorator(handler):
        @token_required
        @wraps(handler)
        def wrapped(*args, **kwargs):
            role = request.current_user.get("role")
            if role not in allowed:
                return error("Acces interdit. Permissions insuffisantes.", 403)
            return handler(*args, **kwargs)

        return wrapped

    return decorator

# ==================== FONCTIONS D'ENRICHISSEMENT ====================
def enrich_patient(patient: dict[str, Any]) -> dict[str, Any]:
    item = dict(patient)
    item["priority"] = normalize_priority(item.get("priority"), "normal")
    item["status"] = normalize_patient_status(item.get("status"), "active")
    return item

def enrich_appointment(appointment: dict[str, Any], patient_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    patient_map = patient_map or get_patient_map()
    item = dict(appointment)
    patient = patient_map.get(to_int(item.get("patient_id")))
    item["patient_name"] = patient.get("full_name") if patient else item.get("patient_name", "Inconnu")
    item["priority"] = normalize_priority(item.get("priority"), "normal")
    item["status"] = normalize_appointment_status(item.get("status"), "scheduled")
    return item

def enrich_prescription(prescription: dict[str, Any], patient_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    patient_map = patient_map or get_patient_map()
    item = dict(prescription)
    patient = patient_map.get(to_int(item.get("patient_id")))
    item["patient_name"] = patient.get("full_name") if patient else item.get("patient_name", "Inconnu")
    return item

def enrich_lab_test(test: dict[str, Any], patient_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    patient_map = patient_map or get_patient_map()
    item = dict(test)
    patient = patient_map.get(to_int(item.get("patient_id")))
    item["patient_name"] = patient.get("full_name") if patient else item.get("patient_name", "Inconnu")
    item["priority"] = normalize_priority(item.get("priority"), "normal")
    return item

def enrich_care_log(care_log: dict[str, Any], patient_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    patient_map = patient_map or get_patient_map()
    item = dict(care_log)
    patient = patient_map.get(to_int(item.get("patient_id")))
    item["patient_name"] = patient.get("full_name") if patient else item.get("patient_name", "Inconnu")
    return item

def enrich_invoice(invoice: dict[str, Any], patient_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    patient_map = patient_map or get_patient_map()
    item = dict(invoice)
    patient = patient_map.get(to_int(item.get("patient_id")))
    item["patient_name"] = patient.get("full_name") if patient else item.get("patient_name", "Inconnu")
    item["status"] = normalize_invoice_status(item.get("status"), "unpaid")
    if not isinstance(item.get("line_items"), list):
        item["line_items"] = build_line_items(item.get("description", ""), to_float(item.get("amount", 0)), None)
    return item

# ==================== SEED SUPER ADMIN (VERSION CORRIGÉE) ====================
def seed_default_admin() -> None:
    """Crée le super admin au démarrage si inexistant (avec logs visibles)"""
    try:
        print("🔍 Vérification du super admin...")
        
        # Vérifier si un super admin existe déjà
        response = supabase.table(USERS_TABLE).select("*").eq("role", "super_admin").limit(1).execute()
        existing_admin = response.data[0] if response.data else None
        
        if existing_admin:
            print(f"✅ Super admin déjà présent: {existing_admin.get('email')}")
            return
        
        print("📝 Création du super admin...")
        
        # Créer le super admin
        admin_data = {
            "name": SUPER_ADMIN_NAME,
            "email": SUPER_ADMIN_EMAIL,
            "password_hash": generate_password_hash(SUPER_ADMIN_PASSWORD),
            "role": "super_admin",
            "is_active": True,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        
        insert_response = supabase.table(USERS_TABLE).insert(admin_data).execute()
        
        if insert_response.data and len(insert_response.data) > 0:
            new_admin = insert_response.data[0]
            print(f"✅ Super admin créé avec succès!")
            print(f"   Email: {SUPER_ADMIN_EMAIL}")
            print(f"   Nom: {SUPER_ADMIN_NAME}")
            print(f"   ID: {new_admin.get('id')}")
            
            # Ajouter un audit log
            try:
                supabase.table(AUDIT_TABLE).insert({
                    "action": "SEED",
                    "entity_type": "user",
                    "entity_id": new_admin.get('id'),
                    "user_id": new_admin.get('id'),
                    "user_name": SUPER_ADMIN_NAME,
                    "details": "Compte super administrateur créé automatiquement au démarrage",
                    "created_at": now_iso(),
                }).execute()
                print("📝 Audit log ajouté")
            except Exception as audit_error:
                print(f"⚠️ Erreur audit log (non bloquante): {audit_error}")
        else:
            print("❌ Échec: Aucune donnée retournée après insertion")
            
    except Exception as e:
        print(f"❌ ERREUR CRITIQUE lors de la création du super admin: {e}")
        print(f"   Type: {type(e).__name__}")
        print(f"   Détails: {str(e)}")
        # Ne pas masquer l'erreur pour le debugging

# ==================== ROUTES API ====================
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "api": f"http://{request.host}/api",
            "database": "supabase",
            "timestamp": now_iso(),
        }
    )

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = safe_json()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    role = str(data.get("role", "reception")).strip().lower()

    if len(name) < 2:
        return error("Le nom doit contenir au moins 2 caracteres.", 422)
    if "@" not in email:
        return error("Email invalide.", 422)
    if len(password) < 8:
        return error("Le mot de passe doit contenir au moins 8 caracteres.", 422)
    if role not in PUBLIC_REGISTRATION_ROLES:
        return error("Role invalide pour une inscription publique.", 422)
    if get_user_by_email(email):
        return error("Cet email est deja utilise.", 422)

    user = insert_row(
        USERS_TABLE,
        {
            "name": name,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": role,
            "is_active": True,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "user", user, f"Inscription: {email} ({role})", user["id"])
    return jsonify({"user": public_user(user), "token": create_token(user)}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = safe_json()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    user = get_user_by_email(email)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return error("Email ou mot de passe incorrect.", 401)
    if not user.get("is_active", True):
        return error("Compte desactive.", 403)

    add_audit("LOGIN", "user", user, f"Connexion: {email}", user["id"])
    return jsonify({"user": public_user(user), "token": create_token(user)})

@app.route("/api/auth/me", methods=["GET"])
@token_required
def auth_me():
    return jsonify({"user": public_user(request.current_user)})

# Route de secours pour créer l'admin manuellement (optionnel)
@app.route("/api/admin/setup", methods=["POST"])
def setup_admin():
    """Route de secours pour créer le super admin (à désactiver après utilisation)"""
    try:
        # Vérifier si admin existe
        existing = supabase.table(USERS_TABLE).select("*").eq("email", SUPER_ADMIN_EMAIL).limit(1).execute()
        
        if existing.data and len(existing.data) > 0:
            return jsonify({
                "message": "Super admin existe déjà",
                "email": SUPER_ADMIN_EMAIL,
                "role": existing.data[0].get("role")
            }), 200
        
        # Créer l'admin
        admin_data = {
            "name": SUPER_ADMIN_NAME,
            "email": SUPER_ADMIN_EMAIL,
            "password_hash": generate_password_hash(SUPER_ADMIN_PASSWORD),
            "role": "super_admin",
            "is_active": True,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        
        result = supabase.table(USERS_TABLE).insert(admin_data).execute()
        
        if result.data and len(result.data) > 0:
            return jsonify({
                "message": "Super admin créé avec succès",
                "email": SUPER_ADMIN_EMAIL,
                "warning": "Changez ce mot de passe immédiatement!"
            }), 201
        else:
            return jsonify({"error": "Échec de création"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/patients", methods=["GET"])
@roles_required(*PATIENT_READ_ROLES)
def get_patients():
    search = str(request.args.get("search", "")).strip().lower()
    patients = [enrich_patient(item) for item in query_table(PATIENTS_TABLE, order="created_at", desc=True)]
    if search:
        patients = [patient for patient in patients if enrich_patient_search(patient, search)]
    return jsonify(patients)

@app.route("/api/patients", methods=["POST"])
@roles_required(*PATIENT_WRITE_ROLES)
def create_patient():
    data = safe_json()
    full_name = str(data.get("full_name", "")).strip()
    if not full_name:
        return error("Le nom complet est requis.", 422)

    patient = insert_row(
        PATIENTS_TABLE,
        {
            "full_name": full_name,
            "phone": str(data.get("phone", "")).strip(),
            "email": str(data.get("email", "")).strip(),
            "date_of_birth": data.get("date_of_birth") or None,
            "gender": str(data.get("gender", "")).strip(),
            "blood_type": str(data.get("blood_type", "")).strip(),
            "address": str(data.get("address", "")).strip(),
            "status": normalize_patient_status(data.get("status"), "active"),
            "allergies": str(data.get("allergies", "")).strip(),
            "medical_history": str(data.get("medical_history", "")).strip(),
            "emergency_contact": str(data.get("emergency_contact", "")).strip(),
            "insurance": str(data.get("insurance", "")).strip(),
            "doctor_notes": str(data.get("doctor_notes", "")).strip(),
            "priority": normalize_priority(data.get("priority"), "normal"),
            "room_number": str(data.get("room_number", "")).strip(),
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "patient", request.current_user, f"Patient cree: {full_name}", patient["id"])
    return jsonify(enrich_patient(patient)), 201

@app.route("/api/patients/<int:patient_id>", methods=["GET"])
@roles_required(*PATIENT_READ_ROLES)
def get_patient(patient_id: int):
    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)
    return jsonify(enrich_patient(patient))

@app.route("/api/patients/<int:patient_id>", methods=["PUT"])
@roles_required(*PATIENT_WRITE_ROLES)
def update_patient(patient_id: int):
    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    data = safe_json()
    payload = {}
    mapping = [
        "full_name",
        "phone",
        "email",
        "date_of_birth",
        "gender",
        "blood_type",
        "address",
        "allergies",
        "medical_history",
        "emergency_contact",
        "insurance",
        "doctor_notes",
        "room_number",
    ]
    for key in mapping:
        if key in data:
            payload[key] = str(data.get(key, "")).strip() if data.get(key) is not None else None
    if "status" in data:
        payload["status"] = normalize_patient_status(data.get("status"), patient.get("status", "active"))
    if "priority" in data:
        payload["priority"] = normalize_priority(data.get("priority"), patient.get("priority", "normal"))

    updated = update_row(PATIENTS_TABLE, patient_id, payload)
    add_audit("UPDATE", "patient", request.current_user, f"Patient modifie: {updated['full_name']}", patient_id)
    return jsonify(enrich_patient(updated))

@app.route("/api/patients/<int:patient_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_patient(patient_id: int):
    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)
    delete_row(PATIENTS_TABLE, patient_id)
    add_audit("DELETE", "patient", request.current_user, f"Patient supprime: {patient['full_name']}", patient_id)
    return jsonify({"message": "Patient supprime."})

@app.route("/api/patients/<int:patient_id>/appointments", methods=["GET"])
@roles_required(*PATIENT_READ_ROLES)
def get_patient_appointments(patient_id: int):
    appointments = query_table(APPOINTMENTS_TABLE, filters={"patient_id": patient_id}, order="date", desc=True)
    patient_map = get_patient_map()
    return jsonify([enrich_appointment(item, patient_map) for item in appointments])

@app.route("/api/patients/<int:patient_id>/prescriptions", methods=["GET"])
@roles_required(*PATIENT_READ_ROLES)
def get_patient_prescriptions(patient_id: int):
    prescriptions = query_table(PRESCRIPTIONS_TABLE, filters={"patient_id": patient_id}, order="created_at", desc=True)
    patient_map = get_patient_map()
    return jsonify([enrich_prescription(item, patient_map) for item in prescriptions])

@app.route("/api/patients/<int:patient_id>/lab-results", methods=["GET"])
@roles_required(*PATIENT_READ_ROLES)
def get_patient_lab_results(patient_id: int):
    tests = query_table(LAB_TESTS_TABLE, filters={"patient_id": patient_id}, order="completed_date", desc=True)
    patient_map = get_patient_map()
    completed = [item for item in tests if item.get("status") == "completed"]
    return jsonify([enrich_lab_test(item, patient_map) for item in completed])

@app.route("/api/appointments", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_appointments():
    patient_map = get_patient_map()
    appointments = query_table(APPOINTMENTS_TABLE, order="date", desc=True)
    return jsonify([enrich_appointment(item, patient_map) for item in appointments])

@app.route("/api/appointments", methods=["POST"])
@roles_required(*APPOINTMENT_ROLES)
def create_appointment():
    data = safe_json()
    patient_id = to_int(data.get("patient_id"))
    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    date = data.get("date")
    appointment_type = str(data.get("type", "")).strip()
    if not date or not appointment_type:
        return error("Patient, date et type sont requis.", 422)

    appointment = insert_row(
        APPOINTMENTS_TABLE,
        {
            "patient_id": patient_id,
            "date": date,
            "type": appointment_type,
            "duration": max(5, to_int(data.get("duration"), 30)),
            "notes": str(data.get("notes", "")).strip(),
            "status": normalize_appointment_status(data.get("status"), "scheduled"),
            "priority": normalize_priority(data.get("priority"), "normal"),
            "doctor_id": request.current_user["id"],
            "doctor_name": request.current_user["name"],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "appointment", request.current_user, f"RDV cree: {patient['full_name']} le {date}", appointment["id"])
    return jsonify(enrich_appointment(appointment, {patient["id"]: patient})), 201

@app.route("/api/appointments/<int:appointment_id>/status", methods=["PUT"])
@roles_required(*APPOINTMENT_ROLES)
def update_appointment_status(appointment_id: int):
    appointment = get_one(APPOINTMENTS_TABLE, appointment_id)
    if not appointment:
        return error("Rendez-vous introuvable.", 404)

    data = safe_json()
    status = normalize_appointment_status(data.get("status"), "")
    if not status:
        return error("Statut invalide.", 422)

    updated = update_row(APPOINTMENTS_TABLE, appointment_id, {"status": status})
    add_audit("UPDATE", "appointment", request.current_user, f"RDV #{appointment_id} -> {status}", appointment_id)
    return jsonify(enrich_appointment(updated))

@app.route("/api/prescriptions", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_prescriptions():
    patient_map = get_patient_map()
    prescriptions = query_table(PRESCRIPTIONS_TABLE, order="created_at", desc=True)
    return jsonify([enrich_prescription(item, patient_map) for item in prescriptions])

@app.route("/api/prescriptions", methods=["POST"])
@roles_required(*PRESCRIPTION_WRITE_ROLES)
def create_prescription():
    data = safe_json()
    patient_id = to_int(data.get("patient_id"))
    medication = str(data.get("medication", "")).strip()
    if not patient_id or not medication:
        return error("Patient et medicament sont requis.", 422)

    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    prescription = insert_row(
        PRESCRIPTIONS_TABLE,
        {
            "patient_id": patient_id,
            "medication": medication,
            "dosage": str(data.get("dosage", "")).strip(),
            "frequency": str(data.get("frequency", "")).strip(),
            "start_date": data.get("start_date") or None,
            "end_date": data.get("end_date") or None,
            "status": str(data.get("status", "active")).strip() or "active",
            "doctor_id": request.current_user["id"],
            "doctor_name": request.current_user["name"],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "prescription", request.current_user, f"Prescription: {medication} pour {patient['full_name']}", prescription["id"])
    return jsonify(enrich_prescription(prescription, {patient["id"]: patient})), 201

@app.route("/api/laboratory/tests", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_laboratory_tests():
    patient_map = get_patient_map()
    tests = query_table(LAB_TESTS_TABLE, order="request_date", desc=True)
    return jsonify([enrich_lab_test(item, patient_map) for item in tests])

@app.route("/api/laboratory/tests", methods=["POST"])
@roles_required(*LAB_ROLES)
def create_laboratory_test():
    data = safe_json()
    patient_id = to_int(data.get("patient_id"))
    test_type = str(data.get("test_type", "")).strip()
    if not patient_id or not test_type:
        return error("Patient et type d'analyse sont requis.", 422)

    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    test = insert_row(
        LAB_TESTS_TABLE,
        {
            "patient_id": patient_id,
            "test_type": test_type,
            "notes": str(data.get("notes", "")).strip(),
            "status": "pending",
            "priority": normalize_priority(data.get("priority"), "normal"),
            "result": "",
            "observations": "",
            "request_date": now_iso(),
            "completed_date": None,
            "requested_by": request.current_user["id"],
            "requested_by_name": request.current_user["name"],
            "technician_name": "",
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "laboratory_test", request.current_user, f"Analyse: {test_type} pour {patient['full_name']}", test["id"])
    return jsonify(enrich_lab_test(test, {patient["id"]: patient})), 201

@app.route("/api/laboratory/tests/<int:test_id>", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_laboratory_test(test_id: int):
    test = get_one(LAB_TESTS_TABLE, test_id)
    if not test:
        return error("Analyse introuvable.", 404)
    return jsonify(enrich_lab_test(test))

@app.route("/api/laboratory/tests/<int:test_id>/result", methods=["PUT"])
@roles_required("super_admin", "laboratoire")
def save_laboratory_result(test_id: int):
    test = get_one(LAB_TESTS_TABLE, test_id)
    if not test:
        return error("Analyse introuvable.", 404)

    data = safe_json()
    payload = {
        "result": str(data.get("result", "")).strip(),
        "observations": str(data.get("observations", "")).strip(),
        "status": "completed",
        "completed_date": now_iso(),
        "technician_name": request.current_user["name"],
    }
    updated = update_row(LAB_TESTS_TABLE, test_id, payload)
    add_audit("UPDATE", "laboratory_test", request.current_user, f"Resultat ajoute: analyse #{test_id}", test_id)
    return jsonify(enrich_lab_test(updated))

@app.route("/api/laboratory/tests/<int:test_id>/result", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_laboratory_result(test_id: int):
    test = get_one(LAB_TESTS_TABLE, test_id)
    if not test:
        return error("Analyse introuvable.", 404)
    return jsonify(enrich_lab_test(test))

@app.route("/api/laboratory/results", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_laboratory_results():
    patient_map = get_patient_map()
    tests = query_table(LAB_TESTS_TABLE, order="completed_date", desc=True)
    completed = [item for item in tests if item.get("status") == "completed"]
    return jsonify([enrich_lab_test(item, patient_map) for item in completed])

@app.route("/api/care", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_care_logs():
    patient_map = get_patient_map()
    care_logs = query_table(CARE_LOGS_TABLE, order="date", desc=True)
    return jsonify([enrich_care_log(item, patient_map) for item in care_logs])

@app.route("/api/care", methods=["POST"])
@roles_required(*CARE_ROLES)
def create_care_log():
    data = safe_json()
    patient_id = to_int(data.get("patient_id"))
    care_type = str(data.get("care_type", "")).strip()
    if not patient_id or not care_type:
        return error("Patient et type de soin sont requis.", 422)

    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    care_log = insert_row(
        CARE_LOGS_TABLE,
        {
            "patient_id": patient_id,
            "care_type": care_type,
            "description": str(data.get("description", "")).strip(),
            "date": now_iso(),
            "performed_by": request.current_user["id"],
            "performed_by_name": request.current_user["name"],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "care", request.current_user, f"Soin: {care_type} pour {patient['full_name']}", care_log["id"])
    return jsonify(enrich_care_log(care_log, {patient["id"]: patient})), 201

@app.route("/api/pharmacy", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_pharmacy_items():
    items = query_table(PHARMACY_TABLE, order="medication_name")
    return jsonify(items)

@app.route("/api/pharmacy", methods=["POST"])
@roles_required(*PHARMACY_ROLES)
def create_pharmacy_item():
    data = safe_json()
    medication_name = str(data.get("medication_name", "")).strip()
    if not medication_name:
        return error("Le nom du medicament est requis.", 422)

    item = insert_row(
        PHARMACY_TABLE,
        {
            "medication_name": medication_name,
            "quantity": max(0, to_int(data.get("quantity"), 0)),
            "unit": str(data.get("unit", "comprime(s)")).strip(),
            "threshold": max(0, to_int(data.get("threshold"), 10)),
            "expiry_date": data.get("expiry_date") or None,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "pharmacy", request.current_user, f"Medicament ajoute: {medication_name}", item["id"])
    return jsonify(item), 201

@app.route("/api/pharmacy/<int:medication_id>", methods=["GET"])
@roles_required(*PHARMACY_ROLES)
def get_pharmacy_item(medication_id: int):
    item = get_one(PHARMACY_TABLE, medication_id)
    if not item:
        return error("Medicament introuvable.", 404)
    return jsonify(item)

@app.route("/api/pharmacy/<int:medication_id>/stock", methods=["PUT"])
@roles_required(*PHARMACY_ROLES)
def update_stock(medication_id: int):
    item = get_one(PHARMACY_TABLE, medication_id)
    if not item:
        return error("Medicament introuvable.", 404)

    data = safe_json()
    quantity = max(0, to_int(data.get("quantity"), 0))
    operation = str(data.get("operation", "set")).strip().lower()
    current_quantity = to_int(item.get("quantity"), 0)
    if operation == "add":
        new_quantity = current_quantity + quantity
    elif operation == "remove":
        new_quantity = max(0, current_quantity - quantity)
    else:
        new_quantity = quantity

    updated = update_row(PHARMACY_TABLE, medication_id, {"quantity": new_quantity})
    add_audit("UPDATE", "pharmacy", request.current_user, f"Stock modifie: {item['medication_name']} -> {new_quantity}", medication_id)
    return jsonify(updated)

@app.route("/api/billing", methods=["GET"])
@roles_required(*STAFF_ROLES)
def get_invoices():
    patient_map = get_patient_map()
    invoices = query_table(INVOICES_TABLE, order="created_at", desc=True)
    return jsonify([enrich_invoice(item, patient_map) for item in invoices])

@app.route("/api/billing", methods=["POST"])
@roles_required(*BILLING_ROLES)
def create_invoice():
    data = safe_json()
    patient_id = to_int(data.get("patient_id"))
    amount = max(0.0, to_float(data.get("amount"), 0))
    if not patient_id or amount <= 0:
        return error("Patient et montant valide sont requis.", 422)

    patient = get_patient_by_id(patient_id)
    if not patient:
        return error("Patient introuvable.", 404)

    description = str(data.get("description", "")).strip()
    invoice = insert_row(
        INVOICES_TABLE,
        {
            "invoice_number": generate_invoice_number(),
            "patient_id": patient_id,
            "amount": amount,
            "description": description,
            "status": "unpaid",
            "line_items": build_line_items(description, amount, data.get("items")),
            "created_by": request.current_user["id"],
            "created_by_name": request.current_user["name"],
            "paid_at": None,
            "paid_by_user_id": None,
            "paid_by_name": "",
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    add_audit("CREATE", "invoice", request.current_user, f"Facture {invoice['invoice_number']}: {amount} FCFA pour {patient['full_name']}", invoice["id"])
    return jsonify(enrich_invoice(invoice, {patient["id"]: patient})), 201

@app.route("/api/billing/<int:invoice_id>/pay", methods=["PUT"])
@roles_required(*BILLING_ROLES)
def mark_invoice_paid(invoice_id: int):
    invoice = get_one(INVOICES_TABLE, invoice_id)
    if not invoice:
        return error("Facture introuvable.", 404)

    updated = update_row(
        INVOICES_TABLE,
        invoice_id,
        {
            "status": "paid",
            "paid_at": now_iso(),
            "paid_by_user_id": request.current_user["id"],
            "paid_by_name": request.current_user["name"],
        },
    )
    add_audit("UPDATE", "invoice", request.current_user, f"Facture {updated['invoice_number']} payee", invoice_id)
    return jsonify(enrich_invoice(updated))

@app.route("/api/audit", methods=["GET"])
@roles_required(*AUDIT_ROLES)
def get_audit_logs():
    logs = query_table(AUDIT_TABLE, order="created_at", desc=True, limit=100)
    return jsonify(logs)

# ==================== POINT D'ENTRÉE ====================
if __name__ == "__main__":
    print("=" * 50)
    print("USHUDa Hospital API - Supabase")
    print("=" * 50)
    seed_default_admin()  # Version corrigée avec logs
    print(f"🌐 API: http://{HOST}:{PORT}/api")
    print(f"🗄️ Base de donnees: Supabase")
    print("=" * 50)
    app.run(host=HOST, port=PORT, debug=DEBUG)
