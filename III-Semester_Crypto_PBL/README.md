# 🔒 SecureChain - Blockchain-based Secure Messaging

A decentralized, secure messaging application built on blockchain technology that provides end-to-end encrypted messaging between users while maintaining an immutable record of all transactions on the blockchain.

## ✨ Features

### 🔐 User Authentication
- Secure user registration and login system
- Session management
- Password hashing with bcrypt

### 💬 Secure Messaging
- End-to-end encrypted messages
- Real-time message status tracking
- Message history and threading

### ⛓️ Blockchain Integration
- Immutable message ledger
- Transaction verification
- Decentralized storage

### 👨‍💼 Admin Dashboard
- User management
- System monitoring
- Blockchain explorer

## 🛠️ Technology Stack

| Component        | Technology           |
|----------------|---------------------|
| **Frontend**   | HTML5, CSS3, JavaScript |
| **Backend**    | Python (Flask)       |
| **Database**   | SQLite              |
| **Blockchain** | Custom Implementation |
| **Security**   | bcrypt, Custom Crypto |

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Node.js (for frontend dependencies)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Crypto_PBL.git
   cd Crypto_PBL
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database**
   ```bash
   python migrate_db.py
   ```

### Running the Application

1. **Start the Flask server**
   ```bash
   python node.py
   ```

2. **Access the application**
   Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

## 📂 Project Structure

```
Crypto_PBL/
├── __pycache__/           # Compiled Python files
├── static/                # Static files (CSS, JS, images)
│   └── style.css          # Main stylesheet
├── templates/             # HTML templates
│   ├── messages.html      # Messaging interface
│   ├── signup.html        # User registration
│   └── status.html        # System status
├── auth.py               # Authentication logic
├── blockchain.json       # Blockchain data storage
├── blockchain.py         # Blockchain implementation
├── crypto_utils.py       # Cryptographic functions
├── migrate_db.py         # Database migration script
├── node.py               # Main application file
└── README.md             # Project documentation
```

## 🔍 How It Works

### 1. User Registration & Authentication
- Users sign up with a username and password
- System generates a public/private key pair
- Passwords are hashed using bcrypt

### 2. Secure Messaging
- Messages are encrypted with recipient's public key
- Only intended recipient can decrypt using their private key
- Each message is hashed and added to the blockchain

### 3. Blockchain Integration
- Every message is a transaction in the blockchain
- Blocks contain multiple transactions
- Chain is verified for integrity on each operation

## 🔒 Security Features

- **End-to-End Encryption**: All messages are encrypted
- **Password Security**: bcrypt hashing with salt
- **SQL Injection Protection**: Parameterized queries
- **Session Security**: Secure, encrypted sessions
- **Immutable Ledger**: Tamper-proof message history

## 🌐 API Endpoints

| Method | Endpoint      | Description                     |
|--------|--------------|---------------------------------|
| GET    | /            | Home page                       |
| GET    | /signup      | Registration page               |
| POST   | /signup      | Handle registration             |
| GET    | /login       | Login page                      |
| POST   | /login       | Handle login                    |
| GET    | /logout      | Logout user                     |
| GET    | /messages    | View messages                   |
| POST   | /send        | Send new message                |
| GET    | /blockchain  | Blockchain explorer             |
| GET    | /status      | View node status and statistics |

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch:
   ```bash
   git checkout -b feature/NewFeature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add some NewFeature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/NewFeature
   ```
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Naitik Dhiman**  
B.Tech CSE Student  
III-Semester Project (Cryptography_PBL)

## 📅 Last Updated
February 2024
