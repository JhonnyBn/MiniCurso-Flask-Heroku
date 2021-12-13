import os, json
from app import app, bcrypt
from flask import render_template, request, redirect, url_for

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