from flask_auth import create_app
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)