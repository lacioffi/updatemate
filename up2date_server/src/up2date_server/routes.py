from flask import Blueprint, json, request, jsonify
#from models import Item
from up2date_server.classes import SoftwareReview, SoftwareVersion
from up2date_server.registry import main_registry

api_bp = Blueprint('api', __name__)

@api_bp.route('/', methods=['GET'])
def index():
    return "Working Gr7! :::;)"

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

@api_bp.route('/software/version/<version_id>/add_review', methods=['POST'])
def add_software_review(version_id):
    data = request.get_json() or {}
    data = json.loads(data)
    review = SoftwareReview(data)

    try:
        main_registry.add_version_review(version_id, review)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": "Review added successfully"}), 201

@api_bp.route('/software/<software_name>', methods=['GET'])
def get_software_reviews(software_name):
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
