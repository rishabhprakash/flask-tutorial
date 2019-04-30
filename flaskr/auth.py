import functools

from flask import (
	Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix = '/auth')


# Check if user already logged in/valid session
@bp.before_app_request
def load_logged_in_user():
	user_id = session.get('user_id')

	if user_id is None:
		g.user = None
	else:
		g.user = get_db().execute(
			'SELECT * from user WHERE id = ?', (user_id,)
		).fetchone()


# Route that renders register view
@bp.route('/register', methods=('GET', 'POST'))
def register():

	# If User posts their new credentials to the form to register
	if request.method == 'POST':

		# Validate the credentials aren't empty
		username = request.form['username']
		password = request.form['password']

		db = get_db()
		error = None

		if not username:
			error = 'Username is required!'
		elif not password:
			error = 'Password is required!'

		# Check if user already registered
		elif db.execute(
			'SELECT id FROM user WHERE username = ?', (username,)
		).fetchone() is not None:
			error = 'User {} is already registered.'.format(username)

		# If user not already registered, create a new user
		if error is None:
			db.execute(
				'INSERT INTO user (username, password) VALUES (?, ?)',
				# Hash the password before storing in database
				(username, generate_password_hash(password))
			)

			# Commit update to database
			db.commit()
			return redirect(url_for('auth.login'))

		# Store error message(s)
		flash(error)

	# Return register page template
	return render_template('auth/register.html')

# Route that renders login view
@bp.route('/login', methods=('GET', 'POST'))
def login():

	# If users post their credentials to login
	if request.method == 'POST':

		# Get username and password from form submission
		username = request.form['username']
		password = request.form['password']

		# Connect to database
		db = get_db()
		error = None

		# Find user with submitted uername
		user = db.execute(
			'SELECT * FROM user WHERE username = ?', (username,)

		).fetchone()

		# If cant find user with submitted username - throw error
		if user is None:
			error = 'Incorrect username!'

		# Compare password hash with database record - throw error if mismatch
		elif not check_password_hash(user['password'], password):
			error = 'Incorrect password!'

		# If no errors so far - clear and initialize new session
		if error is None:
			session.clear()
			session['user_id'] = user['id']
			return redirect(url_for('index'))

		# Store error messages
		flash(error)

	# Return login page template
	return render_template('auth/login.html')

# Route for logging out
@bp.route('logout')
def logout():
	session.clear()
	return redirect(url_for('index'))

# Decorator to check if user logged in - other views
def login_required(view):
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
			return redirect(url_for('auth.login'))

		return view(**kwargs)

	return wrapped_view
