from flask import Blueprint, request, jsonify
from db import db
from models import Item

api_bp = Blueprint('api', __name__)

@api_bp.route('/health-check', methods=['GET'])
def health_check():
    return "OK"

@api_bp.route('/items', methods=['GET'])
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
    return jsonify(item.to_dict()), 201