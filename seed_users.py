from backend.db.database import SessionLocal
from backend.db.models import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db = SessionLocal()

# user = User(
#     username="him",
#     password_hash=pwd_context.hash("1234")
# )
user = User(
    username="abc",
    password_hash=pwd_context.hash("1234")
)
db.add(user)
db.commit()
db.close()

print("User inserted")
