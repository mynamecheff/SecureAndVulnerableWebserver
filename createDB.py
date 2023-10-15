from app import app, db  # Import 'app' from the 'app.py' module

with app.app_context():
    db.create_all()
