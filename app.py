import os



from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kingmate_gamer_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gamedata.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html', user=current_user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful! Login now.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image_url = request.form['image_url']
        new_game = Game(title=title, description=description, image_url=image_url, user_id=current_user.id)
        db.session.add(new_game)
        db.session.commit()
        flash('Game added successfully!', 'success')
        return redirect(url_for('games'))
    return render_template('dashboard.html')

@app.route('/games')
def games():
    game_list = Game.query.all()
    return render_template('games.html', games=game_list)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
app.run(host='0.0.0.0', port=port)

