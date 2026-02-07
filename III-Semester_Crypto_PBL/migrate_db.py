import sqlite3
import os

def add_original_message_column():
    db_path = 'securechain.db'  
    print(f"Connecting to database at: {os.path.abspath(db_path)}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:

        cursor.execute("PRAGMA table_info(messages)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'original_message' not in columns:
            print("Adding original_message column to messages table...")
            cursor.execute('''
                ALTER TABLE messages 
                ADD COLUMN original_message TEXT
            ''')
            conn.commit()
            print("Migration completed successfully!")
        else:
            print("original_message column already exists. No migration needed.")
            
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    add_original_message_column()
