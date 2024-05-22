from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from tinydb import TinyDB, Query
from forms import TodoForm, LoginForm, SignupForm

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Add a secret key for session management
db = TinyDB('db.json')
bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    UserQuery = Query()
    user_data = db.get(UserQuery.id == int(user_id))
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'])
    return None

@app.route('/')
@login_required
def index():
    todos = db.search((Query().type == 'todo') & (Query().user_id == current_user.id))
    return render_template('index.html', todos=todos)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_todo():
    form = TodoForm()
    if form.validate_on_submit():
        db.insert({'type': 'todo', 'title': form.title.data, 'description': form.description.data, 'completed': False, 'user_id': current_user.id})
        flash(f'Activity "{form.title.data}" added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_todo.html', form=form)

@app.route('/edit/<int:todo_id>', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    todo = db.get(doc_id=todo_id)
    if todo and todo.get('user_id') == current_user.id:
        form = TodoForm(data=todo)
        if form.validate_on_submit():
            db.update({'title': form.title.data, 'description': form.description.data}, doc_ids=[todo_id])
            flash(f'Activity "{form.title.data}" updated successfully!', 'success')
            return redirect(url_for('index'))
        return render_template('edit_todo.html', form=form)
    else:
        flash('You are not authorized to edit this activity', 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<int:todo_id>', methods=['POST'])
@login_required
def delete_todo(todo_id):
    todo = db.get(doc_id=todo_id)
    if todo and todo.get('user_id') == current_user.id:
        db.remove(doc_ids=[todo_id])
        flash(f'Activity "{todo["title"]}" deleted successfully!', 'success')
    else:
        flash('You are not authorized to delete this activity', 'danger')
    return redirect(url_for('index'))

@app.route('/complete/<int:todo_id>', methods=['POST'])
@login_required
def complete_todo(todo_id):
    todo = db.get(doc_id=todo_id)
    if todo and todo.get('user_id') == current_user.id:
        is_completed = request.form.get('completed') == 'on'
        db.update({'completed': is_completed}, doc_ids=[todo_id])
        flash(f'Activity "{todo["title"]}" marked as {"completed" if is_completed else "not completed"}!', 'success')
    else:
        flash('You are not authorized to update this activity', 'danger')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        UserQuery = Query()
        user_data = db.get((UserQuery.type == 'user') & (UserQuery.username == form.username.data))
        if user_data and bcrypt.check_password_hash(user_data['password'], form.password.data):
            user = User(user_data['id'], user_data['username'], user_data['password'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        UserQuery = Query()
        existing_user = db.get((UserQuery.type == 'user') & (UserQuery.username == form.username.data))
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user_id = len(db.search(UserQuery.type == 'user')) + 1
            db.insert({'type': 'user', 'id': user_id, 'username': form.username.data, 'password': hashed_password})
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
