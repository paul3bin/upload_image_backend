from app.app import app
from app.app import db
from os import path

if __name__ == "__main__":
    if not path.exists("app/user.db"):
        db.create_all()
    app.run(debug=True)