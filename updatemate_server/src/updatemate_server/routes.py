from flask import Blueprint, json, request, jsonify
#from models import Item
from updatemate_server.classes import SoftwareReview, SoftwareVersion
from updatemate_server.registry import main_registry
from updatemate_server.auth import SignatureError
from updatemate_server import captcha

api_bp = Blueprint('api', __name__)

@api_bp.route('/', methods=['GET'])
def index():
    return "Working Gr8! :::;)"

@api_bp.route('/health-check', methods=['GET'])
def health_check():
    return "OK"

@api_bp.route('/software/version', methods=['POST'])
def add_software_version():
    data = request.get_json() or {}
    data = json.loads(data)
    software_version = SoftwareVersion(data)

    try:
        main_registry.add_software_version(software_version)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": "Version added successfully"}), 201

@api_bp.route('/software/version/<version_id>', methods=['GET'])
def get_software_review(version_id):
    try:
        reviews = main_registry.get_version_reviews(version_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"reviews": reviews}), 200

@api_bp.route('/captcha/new', methods=['GET'])
def new_captcha():
    """Issues a fresh CAPTCHA challenge (Section 6.5): a non-developer
    reviewer must solve one of these before add_software_review will
    accept their review. Returns the challenge image, never the answer."""
    return jsonify(captcha.generate_challenge()), 200

@api_bp.route('/software/version/<version_id>/add_review', methods=['POST'])
def add_software_review(version_id):
    data = request.get_json() or {}
    data = json.loads(data)

    try:
        review = SoftwareReview(data)
        main_registry.add_version_review(version_id, review)
    except SignatureError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "message": "Review added successfully",
        "signer_id": review.signer_id,
        "developer_verified": review.developer_verified,
    }), 201

@api_bp.route('/software/<software_name>', methods=['GET'])
def get_software_report(software_name):
    try:
        report = main_registry.get_human_readable_report(software_name)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"report": report}), 200

@api_bp.route('/software/<software_name>/versions', methods=['GET'])
def get_software_versions(software_name):
    try:
        versions = main_registry.get_software_versions(software_name)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"versions": versions}), 200

### Auditor methods
@api_bp.route('/audit/server_key', methods=['GET'])
def get_server_public_key():
    """Returns the server's signing public key (PEM), which an auditor
    fetches once and pins, then uses to verify the signature on every
    signed tree head returned by the routes below (Section 8.2)."""
    try:
        result = main_registry.get_server_public_key()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": {"public_key_pem": result}}), 200

@api_bp.route('/audit', methods=['GET'])
def get_audit_result():
    try:
        result = main_registry.get_root_audit()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/<software_name>', methods=['GET'])
def get_audit_result_by_software_name(software_name):
    try:
        result = main_registry.get_software_audit(software_name)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/version/<version_id>', methods=['GET'])
def get_audit_result_by_software_version(version_id):
    try:
        result = main_registry.get_software_version_audit(version_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

### Lightweight audit: consistency- and inclusion-proof routes.
# Unlike the routes above, these never transmit the underlying tree: they
# return an O(log n) proof an auditor can verify locally against a
# (root_hash, size) pair it already holds, or against a size and index it
# wants to check inclusion for. See SoftwareRegistry.get_*_consistency_proof
# / get_*_inclusion_proof and Section 8.2 of the paper.

@api_bp.route('/audit/consistency', methods=['GET'])
def get_root_consistency_proof():
    size1 = request.args.get('size1', type=int)
    size2 = request.args.get('size2', type=int)
    if size1 is None:
        return jsonify({"error": "'size1' query parameter is required."}), 400
    try:
        result = main_registry.get_root_consistency_proof(size1, size2)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/inclusion', methods=['GET'])
def get_root_inclusion_proof():
    index = request.args.get('index', type=int)
    size = request.args.get('size', type=int)
    if index is None:
        return jsonify({"error": "'index' query parameter is required."}), 400
    try:
        result = main_registry.get_root_inclusion_proof(index, size)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/<software_name>/consistency', methods=['GET'])
def get_software_consistency_proof(software_name):
    size1 = request.args.get('size1', type=int)
    size2 = request.args.get('size2', type=int)
    if size1 is None:
        return jsonify({"error": "'size1' query parameter is required."}), 400
    try:
        result = main_registry.get_software_consistency_proof(software_name, size1, size2)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/<software_name>/inclusion', methods=['GET'])
def get_software_inclusion_proof(software_name):
    index = request.args.get('index', type=int)
    size = request.args.get('size', type=int)
    if index is None:
        return jsonify({"error": "'index' query parameter is required."}), 400
    try:
        result = main_registry.get_software_inclusion_proof(software_name, index, size)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/version/<version_id>/consistency', methods=['GET'])
def get_software_version_consistency_proof(version_id):
    size1 = request.args.get('size1', type=int)
    size2 = request.args.get('size2', type=int)
    if size1 is None:
        return jsonify({"error": "'size1' query parameter is required."}), 400
    try:
        result = main_registry.get_software_version_consistency_proof(version_id, size1, size2)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200

@api_bp.route('/audit/software/version/<version_id>/inclusion', methods=['GET'])
def get_software_version_inclusion_proof(version_id):
    index = request.args.get('index', type=int)
    size = request.args.get('size', type=int)
    if index is None:
        return jsonify({"error": "'index' query parameter is required."}), 400
    try:
        result = main_registry.get_software_version_inclusion_proof(version_id, index, size)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result}), 200
