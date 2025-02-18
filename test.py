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
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Initialize the database
db = SQLAlchemy(app)

# Define User Model
class User(UserMixin, db.Model):  # Added UserMixin
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Increased length for hashed password

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



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



@app.route('/signup', methods=['GET', 'POST'])       
def signup(): 
     if request.method == 'POST':
         name = request.form['name']  
         email = request.form['email']
         password = request.form['password']

         # Check if the user already exists
         existing_user = User.query.filter_by(email=email).first()
         if existing_user:
            
             return redirect(url_for('login'))

         hashed_password = generate_password_hash(password)
         new_user = User(name=name, email=email, password=hashed_password)  
         db.session.add(new_user)
         db.session.commit()
        
         return redirect(url_for('login'))
    
     return render_template("signup.html")




@app.route('/login', methods=['GET', 'POST'])       
def login(): 
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('layout'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
