from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"   

MONGO_URI = "mongodb+srv://naitikdhiman06_db_user:aTHKrOnMxDJtAcQl@securechaindb.xiealsr.mongodb.net/?retryWrites=true&w=majority&appName=SecureChainDB"
client = MongoClient(MONGO_URI)
db = client['securechain_db']        
users = db['users']               


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if users.find_one({"username": username}):
            return "⚠️ Username already exists. Please log in.", 400

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert_one({
            "username": username,
            "password": hashed_pw.decode('utf-8'),
            "public_key": None,
            "private_key": None
        })

        return redirect(url_for('login'))

    return render_template('signup.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = users.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "❌ Invalid username or password", 401

    return render_template('login.html')



@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"""
        <h1>Welcome, {session['username']} 👋</h1>
        <p>You are logged in successfully.</p>
        <a href='/logout'>Logout</a>
        """
    return redirect(url_for('login'))



@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
