from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from pytz import timezone
from io import BytesIO
from collections import defaultdict
import traceback

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# ✅ Neon PostgreSQL setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://neondb_owner:npg_RfFm8hO1SDcN@ep-cool-forest-a1kp9t33-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024  # 15MB max upload size

db = SQLAlchemy(app)
india = timezone('Asia/Kolkata')

# ------------------ Models ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_email = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    image_data = db.Column(db.LargeBinary(length=(2**24)), nullable=True)  # Up to 16MB
    image_mime = db.Column(db.String(50))

# ------------------ Helper ------------------

def get_user(user_id):
    return db.session.get(User, user_id)

def get_recent_chats(user_id):
    user = get_user(user_id)
    if not user:
        return []

    sent = Message.query.filter_by(sender_id=user.id).all()
    received = Message.query.filter_by(receiver_email=user.email).all()

    recent_emails = set()
    for msg in sent:
        recent_emails.add(msg.receiver_email)
    for msg in received:
        sender = get_user(msg.sender_id)
        if sender:
            recent_emails.add(sender.email)

    recent_chats = []
    for email in recent_emails:
        if email == user.email:
            continue
        u = User.query.filter_by(email=email).first()
        if u:
            unread_count = Message.query.filter_by(receiver_email=user.email, sender_id=u.id, read=False).count()
            recent_chats.append({
                'email': u.email,
                'unread_count': unread_count
            })

    def get_last_msg_time(chat):
        other_user = User.query.filter_by(email=chat['email']).first()
        if not other_user:
            return datetime.min
        last_msg = Message.query.filter(
            ((Message.sender_id == user.id) & (Message.receiver_email == chat['email'])) |
            ((Message.receiver_email == user.email) & (Message.sender_id == other_user.id))
        ).order_by(Message.timestamp.desc()).first()
        return last_msg.timestamp if last_msg else datetime.min

    recent_chats.sort(key=get_last_msg_time, reverse=True)
    return recent_chats

# ------------------ Routes ------------------

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # or homepage for non-logged-in users

    user = db.session.get(User, session['user_id'])
    if not user:
        session.pop('user_id', None)  # clear the session if user no longer exists
        return redirect(url_for('login'))

    recent_chats = get_recent_chats(user.id)
    return render_template('private_chat.html', user=user, recent_chats=recent_chats)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form.get('phone')
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, phone=phone, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')

        if not identifier or not password:
            return "Missing fields", 400

        user = User.query.filter((User.email == identifier) | (User.phone == identifier)).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return "Invalid credentials", 401

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chat/<receiver_email>')
def chat(receiver_email):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = get_user(session['user_id'])
    receiver = User.query.filter_by(email=receiver_email).first()
    users = User.query.filter(User.id != user.id).all()

    if not receiver:
        return "Receiver not found."

    messages = Message.query.filter(
        ((Message.sender_id == user.id) & (Message.receiver_email == receiver.email)) |
        ((Message.receiver_email == user.email) & (Message.sender_id == receiver.id))
    ).order_by(Message.timestamp).all()

    now = datetime.now(india)
    grouped = defaultdict(list)

    for msg in messages:
        msg.timestamp = msg.timestamp.astimezone(india)
        date_only = msg.timestamp.date()

        if date_only == now.date():
            label = "Today"
        elif date_only == (now - timedelta(days=1)).date():
            label = "Yesterday"
        else:
            label = msg.timestamp.strftime('%d %B %Y')

        grouped[label].append(msg)

    unread = Message.query.filter_by(receiver_email=user.email, sender_id=receiver.id, read=False).all()
    for m in unread:
        m.read = True
    db.session.commit()

    recent_chats = get_recent_chats(user.id)

    return render_template('private_chat.html', user=user, receiver=receiver, users=users, grouped_messages=grouped, recent_chats=recent_chats)

@app.route('/api/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    content = data.get('content')
    receiver_email = data.get('receiver_email')
    user = get_user(session['user_id'])

    if not content or not receiver_email:
        return jsonify({'error': 'Missing content or receiver'}), 400

    msg = Message(sender_id=user.id, receiver_email=receiver_email, content=content)
    db.session.add(msg)
    db.session.commit()
    msg.timestamp = msg.timestamp.astimezone(india)

    return jsonify({
        'id': msg.id,
        'sender_id': msg.sender_id,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%I:%M %p'),
        'read': msg.read
    })

@app.route('/api/send_file', methods=['POST'])
def send_file_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = get_user(session['user_id'])
    receiver_email = request.form.get('receiver_email')
    file = request.files.get('file')

    if not file or not receiver_email:
        return jsonify({'error': 'Missing file or receiver'}), 400

    try:
        msg = Message(
            sender_id=user.id,
            receiver_email=receiver_email,
            image_data=file.read(),
            image_mime=file.mimetype
        )
        db.session.add(msg)
        db.session.commit()

        return jsonify({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'image_url': url_for('serve_image', msg_id=msg.id),
            'timestamp': msg.timestamp.astimezone(india).strftime('%I:%M %p'),
            'read': msg.read
        })
    except Exception as e:
        return jsonify({'error': f'Failed to save image: {str(e)}'}), 500

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'error': 'Image too large. Max size is 15MB.'}), 413

@app.route('/image/<int:msg_id>')
def serve_image(msg_id):
    msg = db.session.get(Message, msg_id)
    if not msg or not msg.image_data:
        return "Image not found", 404
    return send_file(BytesIO(msg.image_data), mimetype=msg.image_mime)

@app.route('/api/messages/<receiver_email>/<last_id>')
def get_new_messages(receiver_email, last_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = get_user(session['user_id'])
    receiver = User.query.filter_by(email=receiver_email).first()
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    new_messages = Message.query.filter(
        Message.id > int(last_id),
        ((Message.sender_id == user.id) & (Message.receiver_email == receiver.email)) |
        ((Message.receiver_email == user.email) & (Message.sender_id == receiver.id))
    ).order_by(Message.timestamp).all()

    message_data = []
    for m in new_messages:
        data = {
            'id': m.id,
            'sender_id': m.sender_id,
            'timestamp': m.timestamp.astimezone(india).strftime('%I:%M %p'),
            'read': m.read
        }
        if m.content:
            data['content'] = m.content
        if m.image_data:
            data['image_url'] = url_for('serve_image', msg_id=m.id)
        message_data.append(data)

    return jsonify({'messages': message_data})

@app.route('/api/search_user', methods=['POST'])
def search_user():
    data = request.get_json()
    input_value = data.get('input')

    if not input_value:
        return jsonify({'error': 'Input is required'}), 400

    user = User.query.filter((User.email == input_value) | (User.phone == input_value)).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'email': user.email})

# ------------------ Run App ------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
