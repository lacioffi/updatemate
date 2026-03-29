from flask import Blueprint, json, request, jsonify
from db import db
#from models import Item
from up2date_server.classes import SoftwareReview, SoftwareVersion
from up2date_server.app import main_registry

api_bp = Blueprint('api', __name__)

@api_bp.route('/health-check', methods=['GET'])
def health_check():
    return "OK"

@api_bp.route('/software/add_version', methods=['POST'])
def add_software_version():
    data = request.get_json() or {}
    data = json.loads(data)
    software_version = SoftwareVersion(data)

    try:
        main_registry.add_software_version(software_version)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": "Version added successfully"}), 201

@api_bp.route('/software/<version_id>/add_review', methods=['POST'])
def add_software_review(version_id):
    data = request.get_json() or {}
    data = json.loads(data)
    review = SoftwareReview(data)

    try:
        main_registry.add_version_review(version_id, review)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": "Review added successfully"}), 201

""" @api_bp.route('/items', methods=['GET'])
def get_items():
    items = Item.query.order_by(Item.id).all()
    return jsonify([i.to_dict() for i in items])

@api_bp.route('/items', methods=['POST'])
def add_item():
    data = request.get_json() or {}
    name = data.get('name')
    if not name:
        return jsonify({"error": "name is required"}), 400
    item = Item(name=name)
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201 """