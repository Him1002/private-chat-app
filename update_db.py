# update_db.py
import sqlite3

conn = sqlite3.connect('chat.db')
cursor = conn.cursor()

try:
    # Add column to store image paths
    cursor.execute("ALTER TABLE messages ADD COLUMN image_url VARCHAR")
    print("✅ Success: 'image_url' column added.")
except sqlite3.OperationalError:
    print("ℹ️ Note: Column already exists.")

conn.commit()
conn.close()