import os
import uuid
import traceback
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from PIL import Image

# App setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this for production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'pixelated'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'chacha_keys'), exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# RSA keys
rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "staff" or "patient"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    encryption_method = db.Column(db.String(20), nullable=False, default='aes_rsa')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# Create tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def pixelate_image(image_path):
    try:
        img = Image.open(image_path)
        small = img.resize((16, 16), resample=Image.NEAREST)
        pixelated = small.resize(img.size, Image.NEAREST)

        filename = f"{uuid.uuid4().hex}_pixelated.png"
        pixelated_path = os.path.join(app.config['UPLOAD_FOLDER'], 'pixelated', filename)
        pixelated.save(pixelated_path)

        return f"uploads/pixelated/{filename}"
    except Exception as e:
        app.logger.error(f"Pixelation error: {str(e)}")
        return None

# Encryption/Decryption functions
def encrypt_aes_rsa(data):
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_key = cipher_rsa.encrypt(aes_key)

    return enc_key + cipher_aes.nonce + tag + ciphertext

def decrypt_aes_rsa(encrypted):
    enc_key = encrypted[:256]
    nonce = encrypted[256:272]
    tag = encrypted[272:288]
    ciphertext = encrypted[288:]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

def encrypt_chacha20(data):
    key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    return cipher.nonce + cipher.encrypt(data), key

def decrypt_chacha20(encrypted, key):
    nonce = encrypted[:8]
    ciphertext = encrypted[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'staff' if 'lab' in username.lower() else 'patient'

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('staff_home' if user.role == 'staff' else 'patient_dashboard'))
        flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/staff_home')
@login_required
def staff_home():
    if current_user.role != 'staff':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))
    return render_template('staff_home.html')

@app.route('/staff_dashboard', methods=['GET', 'POST'])
@login_required
def staff_dashboard():
    if current_user.role != 'staff':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    role = request.args.get('role', 'patient')
    prefilled_image = request.args.get('prefilled_image')
    
    if request.method == 'POST':
        receiver_username = request.form['receiver']
        subject = request.form['subject']
        body = request.form.get('body', '')
        
        receiver = User.query.filter_by(username=receiver_username).first()
        if not receiver:
            flash("Receiver not found.", "danger")
            return redirect(url_for('staff_dashboard', role=role, prefilled_image=prefilled_image))

        filename = None
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if allowed_file(file.filename):
                filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash("Invalid file type.", "danger")
        elif prefilled_image:
            filename = os.path.basename(prefilled_image)

        # Determine encryption method based on receiver role
        encryption_method = 'aes_rsa' if receiver.role == 'patient' else 'chacha20'
        
        new_message = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            subject=subject,
            body=body,
            image_filename=filename,
            encryption_method=encryption_method
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')
        return redirect(url_for('staff_dashboard', role=role))
    
    users = User.query.filter_by(role=role).all()
    return render_template('staff_dashboard.html', 
                         role=role, 
                         users=users,
                         prefilled_image=prefilled_image)

@app.route('/patient_dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('patient_dashboard.html', messages=messages)

@app.route('/staff_msg')
@login_required
def staff_msg():
    if current_user.role != 'staff':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('staff_msg.html', messages=messages)

@app.route('/view_message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.receiver_id != current_user.id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('patient_dashboard' if current_user.role == 'patient' else 'staff_msg'))

    pixelated_image = None
    decrypted_image = None

    if message.image_filename:
        base_name = os.path.splitext(message.image_filename)[0]
        pixelated_path = os.path.join('uploads', 'pixelated', f"{base_name}_pixelated.png")
        if os.path.exists(os.path.join('static', pixelated_path)):
            pixelated_image = pixelated_path

    if request.method == 'POST' and request.form.get('action') == 'decrypt' and message.image_filename:
        try:
            # Find encrypted file
            encrypted_path = None
            possible_paths = [
                os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', message.image_filename),
                os.path.join(app.config['UPLOAD_FOLDER'], message.image_filename)
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    encrypted_path = path
                    break
            
            if not encrypted_path:
                raise FileNotFoundError("Encrypted file not found")

            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()

            # Determine decryption method
            if message.encryption_method == 'aes_rsa':
                decrypted_data = decrypt_aes_rsa(encrypted_data)
            else:  # chacha20
                key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'chacha_keys', f"{message.sender_id}.bin")
                if not os.path.exists(key_path):
                    raise FileNotFoundError("Decryption key not found")
                
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
                decrypted_data = decrypt_chacha20(encrypted_data, key)

            # Save decrypted image
            dec_filename = f"dec_{uuid.uuid4().hex}_{message.image_filename}"
            dec_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted', dec_filename)
            os.makedirs(os.path.dirname(dec_path), exist_ok=True)
            
            with open(dec_path, 'wb') as f:
                f.write(decrypted_data)
            
            decrypted_image = f"uploads/decrypted/{dec_filename}"
            flash("Image decrypted successfully!", "success")

        except Exception as e:
            flash(f"Decryption failed: {str(e)}", "danger")
            app.logger.error(f"Decryption error: {traceback.format_exc()}")

    return render_template('view_message.html',
                         message=message,
                         pixelated_image=pixelated_image,
                         decrypted_image=decrypted_image)

@app.route('/encrypt_staff', methods=['GET', 'POST'])
@login_required
def encrypt_staff():
    if current_user.role != 'staff':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    result_img = None
    encrypted_filename = None
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'chacha_keys', f"{current_user.id}.bin")

    if request.method == 'POST':
        action = request.form['action']
        
        if action == 'send' and request.form.get('encrypted_filename'):
            return redirect(url_for('staff_dashboard', 
                                 prefilled_image=f"encrypted/{request.form['encrypted_filename']}", 
                                 role='staff'))
        
        file = request.files.get('image')
        if not file or file.filename == '':
            flash("No file selected!", "danger")
            return render_template('encrypt_staff.html', result_img=None)

        filename = secure_filename(file.filename)
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(original_path)

        with open(original_path, 'rb') as f:
            data = f.read()

        if action == 'encrypt':
            try:
                encrypted, key = encrypt_chacha20(data)
                
                # Save key
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                with open(key_path, 'wb') as keyfile:
                    keyfile.write(key)
                
                # Save encrypted file
                enc_filename = f"enc_{uuid.uuid4().hex}_{filename}"
                enc_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', enc_filename)
                os.makedirs(os.path.dirname(enc_path), exist_ok=True)
                
                with open(enc_path, 'wb') as f:
                    f.write(encrypted)
                
                result_img = pixelate_image(original_path)
                encrypted_filename = enc_filename
                flash("Image encrypted successfully!", "success")

            except Exception as e:
                flash(f"Encryption failed: {str(e)}", "danger")

        elif action == 'decrypt':
            try:
                if not os.path.exists(key_path):
                    raise FileNotFoundError("Encryption key not found")
                
                with open(key_path, 'rb') as keyfile:
                    key = keyfile.read()
                
                decrypted_data = decrypt_chacha20(data, key)
                dec_filename = f"dec_{uuid.uuid4().hex}_{filename}"
                dec_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted', dec_filename)
                os.makedirs(os.path.dirname(dec_path), exist_ok=True)
                
                with open(dec_path, 'wb') as f:
                    f.write(decrypted_data)
                
                result_img = f"uploads/decrypted/{dec_filename}"
                flash("Image decrypted successfully!", "success")

            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "danger")

    return render_template('encrypt_staff.html', 
                         result_img=result_img, 
                         encrypted_filename=encrypted_filename)

@app.route('/encrypt_patient', methods=['GET', 'POST'])
@login_required
def encrypt_patient():
    if current_user.role != 'staff':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    result_img = None
    encrypted_filename = None

    if request.method == 'POST':
        action = request.form['action']
        
        if action == 'send' and request.form.get('encrypted_filename'):
            return redirect(url_for('staff_dashboard', 
                                 prefilled_image=f"encrypted/{request.form['encrypted_filename']}", 
                                 role='patient'))
        
        file = request.files.get('image')
        if not file or file.filename == '':
            flash("No file selected!", "danger")
            return render_template('encrypt_patient.html', result_img=None)

        filename = secure_filename(file.filename)
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(original_path)

        with open(original_path, 'rb') as f:
            data = f.read()

        if action == 'encrypt':
            try:
                encrypted = encrypt_aes_rsa(data)
                enc_filename = f"enc_{uuid.uuid4().hex}_{filename}"
                enc_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', enc_filename)
                os.makedirs(os.path.dirname(enc_path), exist_ok=True)
                
                with open(enc_path, 'wb') as f:
                    f.write(encrypted)
                
                result_img = pixelate_image(original_path)
                encrypted_filename = enc_filename
                flash("Image encrypted successfully!", "success")

            except Exception as e:
                flash(f"Encryption failed: {str(e)}", "danger")

        elif action == 'decrypt':
            try:
                decrypted_data = decrypt_aes_rsa(data)
                dec_filename = f"dec_{uuid.uuid4().hex}_{filename}"
                dec_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted', dec_filename)
                os.makedirs(os.path.dirname(dec_path), exist_ok=True)
                
                with open(dec_path, 'wb') as f:
                    f.write(decrypted_data)
                
                result_img = f"uploads/decrypted/{dec_filename}"
                flash("Image decrypted successfully!", "success")

            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "danger")

    return render_template('encrypt_patient.html', 
                         result_img=result_img,
                         encrypted_filename=encrypted_filename)

if __name__ == '__main__':
    app.run(debug=True)