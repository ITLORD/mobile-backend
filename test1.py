from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://mobile:33211@192.168.88.77:3306/mobile_app_db'
app.config['SECRET_KEY'] = '111111'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    files = db.relationship('File', backref='user', lazy=True)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='file', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/files', methods=['GET'])
def get_files():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing authorization token'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        user = User.query.get(data['user_id'])
        files = [{'id': file.id, 'name': file.name} for file in user.files]
        return jsonify({'files': files})
    except:
        return jsonify({'message': 'Invalid token'}), 401


@app.route('/files', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing authorization token'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        user = User.query.get(data['user_id'])
        file = request.files['file']
        if file:
            new_file = File(name=file.filename, user_id=user.id)
            db.session.add(new_file)
            db.session.commit()
            file.save(f'uploads/{new_file.id}_{file.filename}')
            return jsonify({'message': 'File uploaded successfully!'}), 201
        else:
            return jsonify({'message': 'No file selected'}), 400
    except:
        return jsonify({'message': 'Invalid token'}), 401


@app.route('/files/<file_id>/comments', methods=['POST'])
def add_comment(file_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing authorization token'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        user = User.query.get(data['user_id'])
        file = File.query.get(file_id)
        if file.user_id != user.id:
            return jsonify({'message': 'You are not allowed to comment on this file'}), 403
        data = request.get_json()
        new_comment = Comment(text=data['text'], file_id=file.id)
        db.session.add(new_comment)
        db.session.commit()
        return jsonify({'message': 'Comment added successfully!'}), 201
    except:
        return jsonify({'message': 'Invalid token'}), 401


if __name__ == '__main__':
    app.run(debug=True)