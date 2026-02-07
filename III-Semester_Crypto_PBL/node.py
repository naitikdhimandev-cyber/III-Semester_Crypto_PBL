import os
import sqlite3
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
import time
import bcrypt
from blockchain import Blockchain

app = Flask(__name__)
app.secret_key = "p9XJ4uM2-AVb7qLk-39ZtQvH0-fGs18Ry"  #secret key

DATABASE = 'securechain.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

# Initialize database 
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                cipher_text TEXT NOT NULL,
                key_text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',  
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
        
        db.commit()
init_db()

blockchain = Blockchain()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        

        if not username or not password:
            return "Username and password are required", 400
            
        db = get_db()
        cursor = db.cursor()
        

        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone() is not None:
            return "Username already exists. Please choose a different one.", 400
        
        # generate RSA key pair
        from crypto_utils import generate_rsa_key_pair, hash_password
        private_key, public_key = generate_rsa_key_pair()
        
        # hash the password
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (username, password, public_key, private_key)
            VALUES (?, ?, ?, ?)
        ''', (
            username,
            password_hash,
            public_key.decode('utf-8'),
            private_key.decode('utf-8')
        ))
        db.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return "Username and password are required", 400

        db = get_db()
        cursor = db.cursor()
        
        try:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if not user:
                time.sleep(1)  # prevent timing attacks
                return "Invalid username or password", 401
            
            from crypto_utils import verify_password
            if verify_password(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('index'))
            else:
                time.sleep(1)  # Prevent timing attacks
                return "Invalid username or password", 401
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            return "An error occurred during login. Please try again.", 500

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Close database connection after each request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Blockchain Routes
@app.route('/')
def index():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user info from database
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        # If user not found in database, log them out
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('index.html', 
                         chain=blockchain.chain,
                         username=user['username'])

@app.route('/add_block', methods=['POST'])
def add_block():
    if 'username' not in session:
        return "Unauthorized", 401
        
    data = request.form
    cipher_text = data.get('cipher_text')
    encrypted_key = data.get('encrypted_key')

    if not cipher_text or not encrypted_key:
        return "Missing data", 400

    blockchain.add_block(cipher_text, encrypted_key)
    return "Block added successfully!"

@app.route('/chain', methods=['GET'])
def get_chain():
    if 'username' not in session:
        return "Unauthorized", 401
    return jsonify([block.to_dict() for block in blockchain.chain])

@app.route('/messages')
def view_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get all users for the sidebar
    cursor.execute('SELECT id, username FROM users ORDER BY username')
    all_users = cursor.fetchall()
    
    # Get all messages for the current user with status information
    cursor.execute('''
        SELECT 
            m.*, 
            u1.username as sender_username, 
            u2.username as receiver_username,
            CASE 
                WHEN m.status = 'pending' THEN '⏳ Pending Encryption'
                WHEN m.status = 'encrypted' THEN '🔒 Encrypted & Sending'
                WHEN m.status = 'delivered' THEN '✅ Delivered to Blockchain'
                WHEN m.status = 'failed' THEN '❌ Failed'
                ELSE m.status
            END as status_display
        FROM messages m
        JOIN users u1 ON m.sender_id = u1.id
        JOIN users u2 ON m.receiver_id = u2.id
        WHERE m.receiver_id = ? OR m.sender_id = ?
        ORDER BY m.timestamp DESC
    ''', (session['user_id'], session['user_id']))
    
    # Convert SQLite Row objects to dictionaries and add status class
    messages = []
    for msg in cursor.fetchall():
        # Convert SQLite Row to dict
        msg_dict = dict(msg)
        # Add status class for styling
        msg_dict['status_class'] = msg_dict['status'].lower()
        messages.append(msg_dict)
        
    # Get the selected user filter from query parameters
    selected_user_id = request.args.get('user_id', type=int)
    
    # Try to decrypt all messages for the current user (both sent and received)
    decrypted_messages = []
    for msg in messages:
        decrypted_msg = dict(msg)
        
        # For sent messages, we can show the original message directly
        if msg['sender_id'] == session['user_id']:
            # Get the original message and ensure it's a string, not bytes
            original_msg = msg.get('original_message', 'Message content not available')
            if isinstance(original_msg, bytes):
                try:
                    original_msg = original_msg.decode('utf-8')
                except UnicodeDecodeError:
                    original_msg = str(original_msg)
            
            # Clean up any remaining byte string markers
            if original_msg and isinstance(original_msg, str) and original_msg.startswith("b'") and original_msg.endswith("'"):
                original_msg = original_msg[2:-1]  # Remove b' and ' from the string
                
            decrypted_msg['decrypted_text'] = original_msg
            decrypted_messages.append(decrypted_msg)
            continue
            
        # For received messages, try to decrypt
        try:
            from crypto_utils import (
                decrypt_aes_key,
                decrypt_message as decrypt_msg
            )
            
            # Get the receiver's private key
            cursor.execute('SELECT private_key FROM users WHERE id = ?', (session['user_id'],))
            private_key = cursor.fetchone()['private_key'].encode('utf-8')
            
            # Decrypt the AES key with RSA
            aes_key = decrypt_aes_key(msg['key_text'], private_key)
            
            # Decrypt the message with AES and ensure it's a string
            decrypted_text = decrypt_msg(msg['cipher_text'], aes_key)
            
            # Ensure we have a string, not bytes
            if isinstance(decrypted_text, bytes):
                try:
                    decrypted_text = decrypted_text.decode('utf-8')
                except UnicodeDecodeError:
                    decrypted_text = str(decrypted_text)
            
            decrypted_msg['decrypted_text'] = decrypted_text
            
        except Exception as e:
            print(f"Error decrypting message {msg['id']}: {str(e)}")
            decrypted_msg['decryption_error'] = "Unable to decrypt message"
        
        decrypted_messages.append(decrypted_msg)
    
    # Get the final messages (decrypted if available, otherwise original)
    final_messages = decrypted_messages if decrypted_messages else messages
    
    # Format timestamps for display
    from datetime import datetime
    for msg in final_messages:
        if 'timestamp' in msg and msg['timestamp']:
            if isinstance(msg['timestamp'], str):
                # If timestamp is a string, parse it to datetime first
                try:
                    dt = datetime.strptime(msg['timestamp'], '%Y-%m-%d %H:%M:%S')
                    msg['formatted_time'] = dt.strftime('%I:%M %p')
                    msg['formatted_date'] = dt.strftime('%b %d, %Y')
                except (ValueError, TypeError):
                    msg['formatted_time'] = ''
                    msg['formatted_date'] = ''
            else:
                # If it's already a datetime object
                msg['formatted_time'] = msg['timestamp'].strftime('%I:%M %p')
                msg['formatted_date'] = msg['timestamp'].strftime('%b %d, %Y')
    
    # Get all users for the sidebar
    cursor.execute('SELECT id, username FROM users ORDER BY username')
    all_users = [dict(user) for user in cursor.fetchall()]
    
    # Get the selected user filter from query parameters
    selected_user_id = request.args.get('user_id', type=int)
    
    # Filter messages by selected user if a user is selected
    if selected_user_id:
        final_messages = [msg for msg in final_messages 
                         if msg.get('sender_id') == selected_user_id or 
                            msg.get('receiver_id') == selected_user_id]
    
    return render_template('messages.html', 
                         messages=final_messages,
                         all_users=all_users,
                         selected_user_id=selected_user_id,
                         username=session.get('username'))

@app.route('/blockchain')
def blockchain_explorer():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('blockchain.html')

@app.route('/status')
def status():
    """Show node status and connection information."""
    from blockchain import blockchain
    
    # Check blockchain validity
    is_valid, invalid_blocks = blockchain.is_chain_valid()
    
    # Get node status
    local_ip = get_local_ip()
    node_status = {
        'is_online': True,
        'block_count': len(blockchain.chain),
        'is_valid': is_valid,
        'invalid_blocks': invalid_blocks,
        'last_block': blockchain.chain[-1].to_dict() if blockchain.chain else None,
        'peer_count': 0,  # Will be used when we implement P2P
        'pending_transactions': 0  # Could track pending transactions in the future
    }
    
    return render_template('status.html', 
                         local_ip=local_ip,
                         port=5001,
                         node_status=node_status,
                         is_authenticated='user_id' in session)

def encrypt_message(message, receiver_id):
    return f"encrypted_{message}", "encrypted_aes_key"

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Get and validate fields
        receiver_id_str = data.get('receiver_id')
        message = data.get('message')
        
        # Validate inputs
        if not message or not receiver_id_str:
            return jsonify({'error': 'Missing required fields'}), 400
            
        try:
            receiver_id = int(receiver_id_str)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid receiver ID format'}), 400
            
        if receiver_id <= 0:
            return jsonify({'error': 'Invalid receiver ID'}), 400
            
        db = get_db()
        cursor = db.cursor()
        
        # Get sender and receiver information with error handling
        try:
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            sender = cursor.fetchone()
            if not sender:
                print(f"Error: Sender not found with ID {session['user_id']}")
                return jsonify({'error': 'Your account could not be verified. Please log in again.'}), 401
                
            cursor.execute('SELECT * FROM users WHERE id = ?', (receiver_id,))
            receiver = cursor.fetchone()
            
            if not receiver:
                print(f"Error: Receiver not found with ID {receiver_id}")
                return jsonify({'error': 'The recipient could not be found. Please check the recipient ID.'}), 404
                
            if hasattr(receiver, 'keys'):  # It's a Row object
                receiver = {key: receiver[key] for key in receiver.keys()}
                
            if not receiver.get('public_key'):
                print(f"Error: Receiver {receiver_id} has no public key")
                return jsonify({'error': "The recipient's encryption key is missing. Please contact support."}), 500
                
        except sqlite3.Error as e:
            print(f"Database error when fetching user info: {str(e)}")
            return jsonify({'error': 'An error occurred while processing your request. Please try again.'}), 500
            
        # Import crypto utilities
        from crypto_utils import (
            generate_aes_key,
            encrypt_aes_key,
            encrypt_message as encrypt_msg
        )
        
        # Generate a random AES key for this message
        try:
            print("Generating AES key...")
            aes_key = generate_aes_key()
            
            # Debug info
            print(f"Message type before processing: {type(message)}")
            
            # Ensure message is in bytes for encryption
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            print(f"Message type after processing: {type(message)}")
            print(f"AES key type: {type(aes_key)}")
                
            # Encrypt the message with AES
            print(f"Encrypting message with key: {aes_key[:10]}...")  # Debug log
            encrypted_message = encrypt_msg(message, aes_key)
            
            # Encrypt the AES key with the receiver's public key
            print(f"Encrypting AES key with receiver's public key...")
            print(f"Public key type: {type(receiver['public_key'])}")
            
            # Ensure public_key is in bytes
            public_key = receiver['public_key']
            if isinstance(public_key, str):
                public_key = public_key.encode('utf-8')
                
            encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
            

            cursor.execute('''
                INSERT INTO messages 
                (sender_id, receiver_id, cipher_text, key_text, original_message, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ''', (session['user_id'], receiver_id, encrypted_message, encrypted_aes_key, message, 'pending'))
            
            if not cursor.lastrowid:
                raise ValueError("Failed to insert message into database")
                
        except Exception as e:
            print(f"Error during message encryption/storage: {str(e)}")
            return "Error: Failed to encrypt or store your message. Please try again.", 500
        
        # Get the message ID for status updates
        message_id = cursor.lastrowid
        
        # Add the message to the blockchain
        try:
            from blockchain import blockchain
            
            # Add a new block with all message details
            new_block = blockchain.add_block(
                sender_id=session['user_id'],
                receiver_id=receiver_id,
                cipher_text=encrypted_message,
                key_text=encrypted_aes_key
            )
            print(f"Added block #{new_block.index} to the blockchain")
            print(f"Block hash: {new_block.hash}")
            
            # Update message status to delivered
            cursor.execute('''
                UPDATE messages 
                SET status = 'delivered'
                WHERE id = ?
            ''', (message_id,))
            
        except Exception as e:
            print(f"Error adding to blockchain: {str(e)}")

        
        db.commit()
        return jsonify({
            'success': True,
            'message': 'Message sent successfully',
            'message_id': message_id
        })
        
    except ValueError:
        return "Invalid receiver ID", 400
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        return "Failed to send message", 500

def get_local_ip():
    """Get the local IP address of the machine."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

if __name__ == '__main__':
    local_ip = get_local_ip()
    print(f"\n{'*' * 60}")
    print(f"* SecureChain is running!")
    print(f"* Local: http://localhost:5001")
    print(f"* Network: http://{local_ip}:5001")
    print(f"*")
    print(f"* Press Ctrl+C to stop the server")
    print(f"{'*' * 60}\n")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
