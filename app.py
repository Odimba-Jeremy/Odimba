#!/usr/bin/env python3
"""
I HUB HOSPITAL API - BACKEND COMPLET
Optimisé pour rapidité extrême avec mise en cache, connexion pool, et requêtes optimisées
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_caching import Cache
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

# ==================== CONFIGURATION RAPIDE ====================
SUPABASE_URL = "https://figmeixteescztmmprmi.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-Bwv0EUQzME3nZR8ZPoSwTMCaybHRnw_-7Ew"
SECRET_KEY = "ihub_super_secret_key_2024"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))
DEBUG = False
TOKEN_EXPIRY = 86400 * 7  # 7 jours

# ==================== INITIALISATION ====================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = 300

# Cache pour performances extrêmes
cache = Cache(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Connexion Supabase avec pool
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# Constantes tables
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

# Rôles autorisés
ROLES = {
    "public": ["docteur", "infirmier", "laboratoire", "pharmacie", "reception"],
    "staff": ["super_admin", "docteur", "infirmier", "laboratoire", "pharmacie", "reception"],
    "admin_only": ["super_admin"]
}

# ==================== UTILITAIRES PERFORMANTS ====================
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

# ==================== CACHE DÉCORATEUR ====================
def cached(timeout=300):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cache_key = f"{f.__name__}:{request.full_path}"
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

def invalidate_cache(pattern: str = None):
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
        if not token:
            token = request.cookies.get("ihub_session", "")
        if not token:
            return jsonify({"error": "Token requis"}), 401
        try:
            payload = decode_token(token)
            user = supabase.table(TABLES["users"]).select("*").eq("id", payload["id"]).execute()
            if not user.data:
                return jsonify({"error": "Utilisateur introuvable"}), 401
            g.current_user = user.data[0]
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
        supabase.table(TABLES["audit"]).insert({
            "action": action, "entity_type": entity, "entity_id": entity_id,
            "user_id": g.current_user.get("id") if hasattr(g, 'current_user') else None,
            "user_name": g.current_user.get("name") if hasattr(g, 'current_user') else "Systeme",
            "details": details or "", "created_at": now_iso()
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
        "name": name, "email": email, "password_hash": generate_password_hash(password),
        "role": role, "is_active": True, "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["users"]).insert(user_data).execute()
    user = result.data[0]
    token = create_token(user)
    add_audit("CREATE", "user", f"Inscription: {email}", user["id"])
    
    return jsonify({"user": {k: v for k, v in user.items() if k != "password_hash"}, "token": token}), 201

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    return jsonify({"message": "Déconnexion réussie"})

@app.route("/api/auth/me", methods=["GET"])
@token_required
def auth_me():
    return jsonify({"user": {k: v for k, v in g.current_user.items() if k != "password_hash"}})

# ==================== PATIENTS (COMPLET) ====================
@app.route("/api/patients", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(120)
def get_patients():
    search = request.args.get("search", "").strip().lower()
    result = supabase.table(TABLES["patients"]).select("*").order("created_at", desc=True).execute()
    patients = result.data
    
    if search:
        patients = [p for p in patients if search in p.get("full_name", "").lower() 
                    or search in p.get("phone", "").lower() or search in p.get("email", "").lower()]
    
    return jsonify(patients)

@app.route("/api/patients", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
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
    if not result.data:
        return jsonify({"error": "Patient introuvable"}), 404
    return jsonify(result.data[0])

@app.route("/api/patients/<int:patient_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
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

# ==================== APPOINTMENTS (COMPLET) ====================
@app.route("/api/appointments", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_appointments():
    result = supabase.table(TABLES["appointments"]).select("*").order("date", desc=True).execute()
    appointments = result.data
    
    # Enrichir avec noms patients
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
    for apt in appointments:
        apt["patient_name"] = patient_map.get(apt.get("patient_id"), "Inconnu")
    
    return jsonify(appointments)

@app.route("/api/appointments", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
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
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["appointments"]).insert(appointment).execute()
    add_audit("CREATE", "appointment", f"RDV #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/appointments/<int:appointment_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
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

@app.route("/api/appointments/<int:appointment_id>", methods=["DELETE"])
@roles_required("super_admin")
def delete_appointment(appointment_id: int):
    supabase.table(TABLES["appointments"]).delete().eq("id", appointment_id).execute()
    add_audit("DELETE", "appointment", f"RDV #{appointment_id} supprimé", appointment_id)
    invalidate_cache()
    return jsonify({"message": "Rendez-vous supprimé"})

@app.route("/api/appointments/<int:appointment_id>/status", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier", "reception")
def update_appointment_status(appointment_id: int):
    data = fast_json()
    status = normalize_status(data.get("status", ""), ["scheduled", "completed", "cancelled"], "")
    if not status:
        return jsonify({"error": "Statut invalide"}), 422
    
    result = supabase.table(TABLES["appointments"]).update({"status": status, "updated_at": now_iso()}).eq("id", appointment_id).execute()
    add_audit("UPDATE", "appointment", f"Statut RDV #{appointment_id} -> {status}", appointment_id)
    invalidate_cache()
    return jsonify(result.data[0])

# ==================== PRESCRIPTIONS (COMPLET) ====================
@app.route("/api/prescriptions", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(120)
def get_prescriptions():
    result = supabase.table(TABLES["prescriptions"]).select("*").order("created_at", desc=True).execute()
    prescriptions = result.data
    
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
    for p in prescriptions:
        p["patient_name"] = patient_map.get(p.get("patient_id"), "Inconnu")
    
    return jsonify(prescriptions)

@app.route("/api/prescriptions", methods=["POST"])
@roles_required("super_admin", "docteur")
def create_prescription():
    data = fast_json()
    if not data.get("patient_id") or not data.get("medication"):
        return jsonify({"error": "Patient et médicament requis"}), 422
    
    prescription = {
        "patient_id": to_int(data.get("patient_id")),
        "medication": data.get("medication"),
        "dosage": data.get("dosage", ""),
        "frequency": data.get("frequency", ""),
        "start_date": data.get("start_date"),
        "end_date": data.get("end_date"),
        "instructions": data.get("instructions", ""),
        "status": data.get("status", "active"),
        "doctor_id": g.current_user["id"],
        "doctor_name": g.current_user["name"],
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["prescriptions"]).insert(prescription).execute()
    add_audit("CREATE", "prescription", f"Prescription #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/prescriptions/<int:prescription_id>", methods=["PUT"])
@roles_required("super_admin", "docteur")
def update_prescription(prescription_id: int):
    data = fast_json()
    allowed = ["medication", "dosage", "frequency", "start_date", "end_date", "instructions", "status"]
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

# ==================== LABORATORY (COMPLET) ====================
@app.route("/api/laboratory/tests", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_lab_tests():
    result = supabase.table(TABLES["lab_tests"]).select("*").order("request_date", desc=True).execute()
    tests = result.data
    
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
    for t in tests:
        t["patient_name"] = patient_map.get(t.get("patient_id"), "Inconnu")
    
    return jsonify(tests)

@app.route("/api/laboratory/tests", methods=["POST"])
@roles_required("super_admin", "docteur", "laboratoire")
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
        "created_at": now_iso(), "updated_at": now_iso()
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
    result = supabase.table(TABLES["lab_tests"]).select("*").eq("status", "completed").order("completed_date", desc=True).execute()
    tests = result.data
    
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
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

# ==================== CARE LOGS (COMPLET) ====================
@app.route("/api/care", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_care_logs():
    result = supabase.table(TABLES["care"]).select("*").order("date", desc=True).execute()
    care_logs = result.data
    
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
    for c in care_logs:
        c["patient_name"] = patient_map.get(c.get("patient_id"), "Inconnu")
    
    return jsonify(care_logs)

@app.route("/api/care", methods=["POST"])
@roles_required("super_admin", "docteur", "infirmier")
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
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["care"]).insert(care).execute()
    add_audit("CREATE", "care", f"Soin #{result.data[0]['id']}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

@app.route("/api/care/<int:care_id>", methods=["PUT"])
@roles_required("super_admin", "docteur", "infirmier")
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

# ==================== PHARMACY (COMPLET) ====================
@app.route("/api/pharmacy", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_pharmacy():
    result = supabase.table(TABLES["pharmacy"]).select("*").order("medication_name").execute()
    return jsonify(result.data)

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
        "threshold": max(0, to_int(data.get("threshold"), 10)),
        "expiry_date": data.get("expiry_date"),
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["pharmacy"]).insert(item).execute()
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

# ==================== BILLING (COMPLET) ====================
@app.route("/api/billing", methods=["GET"])
@roles_required(*ROLES["staff"])
@cached(60)
def get_invoices():
    result = supabase.table(TABLES["billing"]).select("*").order("created_at", desc=True).execute()
    invoices = result.data
    
    patients = supabase.table(TABLES["patients"]).select("id", "full_name").execute()
    patient_map = {p["id"]: p["full_name"] for p in patients.data}
    for inv in invoices:
        inv["patient_name"] = patient_map.get(inv.get("patient_id"), "Inconnu")
    
    return jsonify(invoices)

@app.route("/api/billing", methods=["POST"])
@roles_required("super_admin", "reception")
def create_invoice():
    data = fast_json()
    if not data.get("patient_id"):
        return jsonify({"error": "Patient requis"}), 422
    
    amount = round(to_float(data.get("amount"), 0), 2)
    if amount <= 0:
        return jsonify({"error": "Montant invalide"}), 422
    
    invoice = {
        "invoice_number": f"FAC-{int(time.time())}-{secrets.token_hex(2).upper()}",
        "patient_id": to_int(data.get("patient_id")),
        "amount": amount,
        "description": data.get("description", ""),
        "status": "unpaid",
        "line_items": data.get("items", []),
        "created_by": g.current_user["id"],
        "created_by_name": g.current_user["name"],
        "created_at": now_iso(), "updated_at": now_iso()
    }
    result = supabase.table(TABLES["billing"]).insert(invoice).execute()
    add_audit("CREATE", "billing", f"Facture #{result.data[0]['id']}: {amount}", result.data[0]["id"])
    invalidate_cache()
    return jsonify(result.data[0]), 201

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
    add_audit("DELETE", "billing", f"Facture #{invoice_id} supprimée", invoice_id)
    invalidate_cache()
    return jsonify({"message": "Facture supprimée"})

# ==================== USERS (COMPLET) ====================
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
        "name": name, "email": email, "password_hash": generate_password_hash(password),
        "role": role, "is_active": True, "created_at": now_iso(), "updated_at": now_iso()
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
@cached(60)
def get_audit_logs():
    result = supabase.table(TABLES["audit"]).select("*").order("created_at", desc=True).limit(500).execute()
    return jsonify(result.data)

# ==================== HEALTH ====================
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": now_iso(), "version": "2.0.0"})

# ==================== SEED SUPER ADMIN ====================
def seed_admin():
    existing = supabase.table(TABLES["users"]).select("id").eq("email", "jeremyodimba322@gmail.com").execute()
    if not existing.data:
        supabase.table(TABLES["users"]).insert({
            "name": "Administrateur", "email": "jeremyodimba322@gmail.com",
            "password_hash": generate_password_hash("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"),
            "role": "super_admin", "is_active": True,
            "created_at": now_iso(), "updated_at": now_iso()
        }).execute()
        print("✅ Super admin créé")

# ==================== LANCEMENT ====================
if __name__ == "__main__":
    print("=" * 50)
    print("🏥 I HUB HOSPITAL API - BACKEND COMPLET")
    print("=" * 50)
    seed_admin()
    print(f"🚀 Serveur démarré sur http://{HOST}:{PORT}")
    print("=" * 50)
    app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)
