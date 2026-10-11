import os
import time
from flask import Flask
from updatemate_server.routes import api_bp

def create_app():
    app = Flask(__name__)
    app.register_blueprint(api_bp)
    return app

def main():
    port = int(os.environ.get('SERVER_PORT', 5000))
    debug = bool(os.environ.get('DEBUG', False))
    app = create_app()
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    main()