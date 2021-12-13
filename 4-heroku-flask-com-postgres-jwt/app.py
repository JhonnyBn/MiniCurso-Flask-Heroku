import os, json
from flask import Flask, jsonify, request, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt_claims
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Setup app config
host = '0.0.0.0'
port = int(os.environ.get('PORT', '5000'))
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'random string') # Change this!

# Setup Flask-JWT-Extended config
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret') # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
jwt = JWTManager(app)

# Setup SQLAlchemy config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:123456@localhost/flask_jwt_auth')
db = SQLAlchemy(app)

class users(db.Model):
	id = db.Column('user_id', db.Integer, primary_key = True)
	username = db.Column(db.String(50), unique=True, nullable=False)
	password = db.Column(db.String(60), nullable=False)
	admin = db.Column(db.Boolean, nullable=False, default=False)

	def __init__(self, username, password, admin=False):
	   self.username = username
	   self.password = password
	   self.admin = admin

# test route
@app.route('/', methods = ["GET","POST"])
def index():
	if users.query.count() < 1:
		try:
			password_hash = bcrypt.generate_password_hash("admin").decode('utf-8')
			admin = users("admin", password_hash, True)
			db.session.add(admin)
			db.session.commit()
		except Exception as error:
			return jsonify({ "Error" : str(error) }), 200
	print(request)
	return request.data


@app.route('/login', methods=['POST'])
def login():
	if not request.is_json:
		return jsonify({ "auth": False, "token": None, "message": "Missing JSON in request" }), 200

	username = request.json.get('user', None)
	password = request.json.get('pwd', None)
	if not username:
		return jsonify({ "auth": False, "token": None, "message": "Missing username parameter"}), 200
	if not password:
		return jsonify({ "auth": False, "token": None, "message": "Missing password parameter"}), 200
	
	user = users.query.filter_by(username=username).first()
	if user is None:
		return jsonify({ "auth": False, "token": None, "message": "Bad username or password"}), 200
	if not bcrypt.check_password_hash(user.password, password):
		return jsonify({ "auth": False, "token": None, "message": "Bad username or password"}), 200
	
	identity = user.id
	user_claims = { 'username': user.username, 'admin': user.admin }
	access_token = create_access_token(identity=identity, user_claims=user_claims)
	return jsonify({ "auth": True, "token": access_token, "message": "Logged in succesfully."}), 200


@app.route('/register', methods = ['POST'])
@jwt_required
def register():
	claims = get_jwt_claims()
	admin = claims.get('admin', False)
	if not admin:
		return jsonify({ "registered": False, "message": "Unauthorized." }), 200
		
	if not request.is_json:
		return jsonify({ "registered": False, "message": "Missing JSON in request" }), 200
	
	username = request.json.get('user', None)
	password = request.json.get('pwd', None)
	admin = request.json.get('admin', None)
	if not username:
		return jsonify({ "registered": False, "message": "Missing username parameter" }), 200
	if not password:
		return jsonify({ "registered": False, "message": "Missing password parameter" }), 200
	if not admin:
		admin = False
	
	user = users.query.filter_by(username=username).first()
	if user is not None:
		return jsonify({ "registered": False, "message": "Username already registered." }), 200
	
	try:
		password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
		user = users(username, password_hash, admin)
		db.session.add(user)
		db.session.commit()
		return jsonify({ "registered": True, "message": "Registered succesfully." }), 200 #redirect(url_for('show_all'))
	except Exception as error:
		return jsonify({ "registered": False, "message": "Error: " + str(error) }), 200
	 
	return jsonify({ "registered": False, "message": "Unexpected error." }), 500


@app.route('/remove', methods = ['POST'])
@jwt_required
def remove():
	if not request.is_json:
		return jsonify({ "removed": False, "message": "Missing JSON in request" }), 200
	
	username = request.json.get('user', None)
	if not username:
		return jsonify({ "removed": False, "message": "Missing username parameter" }), 200
	
	user = users.query.filter_by(username=username).first()
	if user is None:
		return jsonify({ "removed": False, "message": "User not found" }), 200

	claims = get_jwt_claims()
	admin = claims.get('admin', False)
	if not admin:
		password = request.json.get('pwd', None)
		if not password:
			return jsonify({ "removed": False, "message": "Missing password parameter" }), 200
		if not bcrypt.check_password_hash(user.password, password):
			return jsonify({ "removed": False, "message": "Wrong password"}), 200
	
	try:
		db.session.delete(user)
		db.session.commit()
		return jsonify({ "removed": True, "message": "Deleted succesfully." }), 200 #redirect(url_for('show_all'))
	except Exception as error:
		return jsonify({ "removed": False, "message": "Error: " + str(error) }), 200
	 
	return jsonify({ "removed": False, "message": "Unexpected error." }), 500


@app.route('/teste', methods=['GET'])
@jwt_required
def teste():
	um = int(request.args.get('um', '0') or '0', 10)
	dois = int(request.args.get('dois', '0') or '0', 10)
	tres = int(request.args.get('tres', '0') or '0', 10)
	quatro = int(request.args.get('quatro', '0') or '0', 10)
	cinco = int(request.args.get('cinco', '0') or '0', 10)
	seis = int(request.args.get('seis', '0') or '0', 10)
	
	# processamento
	
	return jsonify(	um=um,
					dois=dois,
					tres=tres,
					quatro=quatro,
					cinco=cinco,
					seis=seis	), 200


if __name__ == '__main__':
	db.create_all()
	app.run(host=host, port=port)