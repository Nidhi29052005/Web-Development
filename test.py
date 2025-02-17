# from flask import Flask ,render_template   
# app = Flask(__name__)   # Flask constructor 
  
# # A decorator used to tell the application 
# # which URL is associated function 
# @app.route('/about.html')       
# def about(): 
#     return render_template("about.html")
# @app.route('/code.html')       
# def code(): 
#     return render_template("code.html")
# @app.route('/courses.html')       
# def courses(): 
#     return render_template("courses.html")
# @app.route('/login.html')       
# def login(): 
#     return render_template("login.html")
# @app.route('/')       
# def layout(): 
#     return render_template("layout.html")


  
# app.run(debug=True) 
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ensure tables are created before the app runs
with app.app_context():
    db.create_all()

@app.route('/')       
def layout(): 
    return render_template("layout.html")

@app.route('/about.html')       
def about(): 
    return render_template("about.html")

@app.route('/code.html')       
def code(): 
    return render_template("code.html")

@app.route('/courses.html')       
def courses(): 
    return render_template("courses.html")

@app.route('/login.html', methods=['GET', 'POST'])       
def login(): 
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            hashed_password = generate_password_hash(password)
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Account created and logged in successfully!')
            return redirect(url_for('layout'))
        elif user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('layout'))
        else:
            flash('Invalid email or password')
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template("register.html")

if __name__ == '__main__':
    app.run(debug=True)

