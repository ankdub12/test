from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
NAME_REGEX = re.compile(r'\d')

app = Flask(__name__)
bcrypt =Bcrypt(app)
mysql = MySQLConnector(app,'login')
app.secret_key = "ThisIsSecret"

@app.route('/')
def mails():
	return render_template('index.html')

@app.route('/create' , methods=['POST'])
def user():
	email = request.form['email']
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	password = request.form['password']
	confirm_password = request.form['confirm_password']
	if not EMAIL_REGEX.match(email):
		flash('Invalid email format')
		return redirect('/')
	if NAME_REGEX.search(first_name) or NAME_REGEX.search(last_name):
		flash("letters only")
		return redirect('/')
	if password != confirm_password:
		flash("Password should match")
		return redirect('/')
	if len(password) < 8:
		flash("password should have atleast 8 characters")
		return redirect('/')
	else:
		pw_hash = bcrypt.generate_password_hash(password)
		query = "INSERT INTO usetable (first_name, last_name, email, password) VALUES(:first_name,:last_name,:email,:password )"
		data = {
		'first_name': first_name,
		'last_name': last_name,
		'email': email,
		'password': pw_hash,
		}
		usetable = mysql.query_db(query,data)
		return render_template('success.html')

@app.route('/login')
def showlogin():

	return render_template('loginpage.html')
	
@app.route('/checklogin', methods=['POST'])
def login():
	email = request.form['email']
	password = request.form['password']
	query = "SELECT * FROM usetable WHERE email = :email LIMIT 1"
	data = {
	'email': email
	}
	user = mysql.query_db(query,data)
	if user and bcrypt.check_password_hash(user[0]['password'], password):

  		return render_template('success.html')
 	else:
 		flash("password or email does not match")
 		return redirect('/login')


		
app.run(debug=True)

