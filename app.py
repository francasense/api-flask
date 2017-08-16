from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soufiscal.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    email = db.Column(db.String)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50))
    name_user = db.Column(db.String(10))
    titulo = db.Column(db.String(30))
    valor_inicial = db.Column(db.Float)
    data_inicial = db.Column(db.String(50))
    data_entrega = db.Column(db.String(50))
    data_postagem = db.Column(db.String(50))
    url_foto = db.Column(db.String)
    latitude = db.Column(db.Integer)
    longitude = db.Column(db.Integer)
    descricao = db.Column(db.String(300))
    resposta = db.Column(db.String(400))
    status = db.Column(db.Integer)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
#@token_required
#def get_all_users(current_user):
def get_all_users():

    #if not current_user.admin:
    #    return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'],email=data['email'],password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/reclamacao', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['email'] = todo.email
        todo_data['name_user'] = todo.name_user
        todo_data['titulo'] = todo.titulo
        todo_data['valor_inicial'] = todo.valor_inicial
        todo_data['data_inicial'] = todo.data_inicial
        todo_data['data_entrega'] = todo.data_entrega
        todo_data['data_postagem'] = todo.data_postagem
        todo_data['url_foto'] = todo.url_foto
        todo_data['latitude'] = todo.latitude
        todo_data['longitude'] = todo.longitude
        todo_data['descricao'] = todo.descricao
        todo_data['resposta'] = todo.resposta
        todo_data['status'] = todo.status
        todo_data['user_id'] = todo.user_id




        output.append(todo_data)

    return jsonify({'todos' : output})

@app.route('/todo/<name_user>', methods=['GET'])
@token_required
def get_one_todos(current_user,name_user):
    todos = Todo.query.filter_by(name_user=name_user, user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['email'] = todo.email
        todo_data['name_user'] = todo.name_user
        todo_data['titulo'] = todo.titulo
        todo_data['valor_inicial'] = todo.valor_inicial
        todo_data['data_inicial'] = todo.data_inicial
        todo_data['data_entrega'] = todo.data_entrega
        todo_data['data_postagem'] = todo.data_postagem
        todo_data['url_foto'] = todo.url_foto
        todo_data['latitude'] = todo.latitude
        todo_data['longitude'] = todo.longitude
        todo_data['descricao'] = todo.descricao
        todo_data['resposta'] = todo.resposta
        todo_data['status'] = todo.status
        todo_data['user_id'] = todo.user_id

        output.append(todo_data)

    return jsonify({'todos' : output})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
#def create_todo():
    data = request.get_json()
    new_todo = Todo(email=data['email'], name_user=data['name_user'], titulo=data['titulo'], valor_inicial=data['valor_inicial'], data_inicial=data['data_inicial'], data_entrega=data['data_entrega'], data_postagem=data['data_postagem'], url_foto=data['url_foto'] ,latitude=data['latitude'] ,longitude=data['longitude'] ,descricao=data['descricao'], resposta=data['resposta'], status=data['status'],user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : "Todo created!"})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message' : 'Todo item has been completed!'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'Todo item deleted!'})

if __name__ == '__main__':
    app.run(debug=True)
