from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

# Налаштування секретного ключа для сесій
app.secret_key = 'your_secret_key'

# Налаштування менеджера входу
login_manager = LoginManager()
login_manager.init_app(app)

# Створення тестових даних користувачів з ролями
users = {
    'user1': {'password': 'password1', 'role': 'USER'},
    'admin1': {'password': 'adminpassword', 'role': 'ADMIN'}
}

# Клас користувача
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

# Логіка для завантаження користувача за id
@login_manager.user_loader
def load_user(user_id):
    return User(user_id, users[user_id]['role'])

# Маршрут для авторизації
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            user = User(username, users[username]['role'])
            login_user(user)
            return redirect(url_for('dashboard'))
        return 'Invalid credentials', 401
    return render_template('login.html')

# Маршрут для виходу
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Маршрут для захищеного ресурсу
@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello {current_user.id}, you are logged in as {current_user.role}.'

# Захищений маршрут для користувачів з роллю "USER"
@app.route('/user_area')
@login_required
def user_area():
    if current_user.role != 'USER':
        return redirect(url_for('dashboard'))
    return 'This is the user area.'

# Захищений маршрут для користувачів з роллю "ADMIN"
@app.route('/admin_area')
@login_required
def admin_area():
    if current_user.role != 'ADMIN':
        return redirect(url_for('dashboard'))
    return 'This is the admin area.'

# Головний маршрут
@app.route('/')
def home():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
