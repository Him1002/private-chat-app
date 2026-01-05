from database import SessionLocal, engine
from models import User, Friend, Base
from passlib.context import CryptContext

# 1. Create Tables
Base.metadata.create_all(bind=engine)

db = SessionLocal()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_user(username, password):
    # Check if exists
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return existing
    
    user = User(username=username, password_hash=pwd_context.hash(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"✅ Created user: {username}")
    return user

# 2. Create Users "him" and "alex"
u1 = create_user("him", "1234")
u2 = create_user("raj", "1234")

# 3. Make them Friends (Forcefully)
# Check if friendship exists
friendship = db.query(Friend).filter_by(user_id=u1.id, friend_id=u2.id).first()

if not friendship:
    # A -> B
    f1 = Friend(user_id=u1.id, friend_id=u2.id, status="accepted")
    # B -> A
    f2 = Friend(user_id=u2.id, friend_id=u1.id, status="accepted")
    
    db.add_all([f1, f2])
    db.commit()
    print(f"✅ {u1.username} and {u2.username} are now friends!")
else:
    print("ℹ️  Already friends.")

db.close()