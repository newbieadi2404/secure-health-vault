# ROLE_FIELD_MAP defines which fields are visible to which roles
ROLE_FIELD_MAP = {
    "doctor": [
        "patient_id", "diagnosis", "prescription", "lab_results",
        "timestamp", "sender", "message", "image_data", "image_filename"
    ],
    "nurse": [
        "patient_id", "prescription", "lab_results",
        "timestamp", "sender", "message", "image_filename"
    ],
    "admin": [
        "patient_id", "diagnosis", "prescription", "lab_results",
        "timestamp", "sender", "message", "image_data", "image_filename",
        "audit_info"
    ],
    "patient": [
        "patient_id", "diagnosis", "prescription", "lab_results",
        "timestamp", "sender", "message", "image_data", "image_filename"
    ]
}


def allowed_fields(role):
    if role not in ROLE_FIELD_MAP:
        raise PermissionError("Invalid role")
    return ROLE_FIELD_MAP[role]
