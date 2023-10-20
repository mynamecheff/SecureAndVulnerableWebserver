from app import app, User

user_id = 4

db = app.extensions['sqlalchemy']

with app.app_context():
    user = db.session.query(User).filter_by(id=user_id).first()

    if user:
        user.is_admin = True
        db.session.commit()
        print(f'User {user.username} is now an admin!!')
