import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bootstrap import Bootstrap


app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
# element ten ma zczytać lokalne id sesji
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'POST':
        password_hashed = generate_password_hash(flask.request.values.get("password"), method="pbkdf2:sha256", salt_length=8)
        try:
            new_user = User(
                email=flask.request.values.get('email'),
                password=password_hashed,
                name=flask.request.values.get('name')
            )

            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('secrets', name=new_user.name))
        except:
            flash("User already exist plis log in", category='error')
            return redirect(url_for('login'))

    else:
        return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        inputed_email = flask.request.values.get('email')
        detected_user = User.query.filter_by(email=inputed_email).first()
        if detected_user:
            inputed_password = flask.request.values.get('password')
            hashed_in_password = generate_password_hash(password=inputed_password, method="pbkdf2:sha256", salt_length=8)
            if check_password_hash(pwhash=detected_user.password, password=inputed_password):
                login_user(user=detected_user)
                return redirect(url_for('secrets', name=detected_user.name))
            else:
                flash("Inputed password is invalid plis try again", category="error")
                return render_template("login.html")
        else:
            flash("Inputed Email is invalid plis try again", category="error")
            return render_template("login.html")

    else:
        return render_template("login.html")


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    return send_from_directory('static/files', 'cheat_sheet.pdf', as_attachment=True)
    pass


if __name__ == "__main__":
    app.run(debug=True)
