import os, json
from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'random string')

@app.route('/', methods = ["GET","POST"])
def index():
	return "Hello World!"

@app.route('/home', methods=['GET'])
def home():
	return render_template('home.html')

@app.route('/login', methods=["GET"])
def login():
	return render_template('login.html')

@app.route('/senha', methods=["POST"])
def senha():
	senha = request.json.get('senha', None)
	password_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
	return { "senha": password_hash }, 200

if __name__ == '__main__':
	app.run(host="0.0.0.0", port='5000')