import os
import time
from flask import Flask
from db import db
from routes import api_bp
from sqlalchemy import create_engine
from up2date_server.merkle import SoftwareRegistry

DATA_PATH = "merkle_data/"  # Path to store Merkle trees and data files
main_registry = SoftwareRegistry(DATA_PATH)  # Master registry for all software products

def wait_for_db(db_url, retries=10, delay=1.5):
    """Simple retry loop to wait for Postgres to be ready."""
    for attempt in range(retries):
        try:
            engine = create_engine(db_url)
            conn = engine.connect()
            conn.close()
            return True
        except Exception as e:
            print(f"Waiting for DB (attempt {attempt+1}/{retries})... {e}")
            time.sleep(delay)
    return False

def create_app():
    app = Flask(__name__)
    db_url = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/mydb')
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # wait for DB a bit so `db.create_all()` doesn't fail immediately when starting via docker-compose
    if not wait_for_db(db_url, retries=20, delay=1.5):
        print("Warning: database did not become available in time. The app will still start but DB calls may fail.")

    db.init_app(app)
    app.register_blueprint(api_bp)


if __name__ == '__main__':
    port = int(os.environ.get('SERVER_PORT', 5000))
    app = create_app()
    app.run(host='0.0.0.0', port=port)