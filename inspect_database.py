from app import app, db, User, Message  # Adjust if your file is not named app.py
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    print("📋 Tables in the database:")
    print(inspector.get_table_names())
    print()

    # Print all users
    print("👥 Users:")
    users = User.query.all()
    if users:
        for user in users:
            print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}")
    else:
        print("No users found.")
    print()

    # Print all messages
    print("✉️ Messages:")
    messages = Message.query.all()
    if messages:
        for msg in messages:
            print(f"""
📨 Message ID: {msg.id}
   From User ID: {msg.sender_id}
   To User ID: {msg.receiver_id}
   Subject: {msg.subject}
   Body: {msg.body}
   Image File: {msg.image_filename}
   Encryption Method: {msg.encryption_method}
   Sent At: {msg.timestamp}
            """)
    else:
        print("No messages found.")
with app.app_context():
    inspector = inspect(db.engine)
    
    print("📋 Tables and their columns in the database:\n")
    
    for table_name in inspector.get_table_names():
        print(f"Table: {table_name}")
        columns = inspector.get_columns(table_name)
        for col in columns:
            print(f" - {col['name']} ({col['type']})")
        print()  # Blank line for readability