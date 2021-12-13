import os, json
from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Setup app config
host = '0.0.0.0'
port = int(os.environ.get('PORT', '5000'))
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'random string') # Troque isso!

@app.route('/', methods = ["GET","POST"])
def index():
	return "Hello World!"

@app.route('/home', methods=['GET'])
def home():
	return render_template('home.html')

@app.route('/login', methods=['GET'])
def login():
	return render_template('login.html')

@app.route('/senha', methods=['POST'])
def senha():
	senha = request.json.get('senha', None)
	
	if senha is None:
		return { "senha": "" }, 200
	
	password_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
	return { "senha": password_hash }, 200

if __name__ == '__main__':
	app.run(host=host, port=port)