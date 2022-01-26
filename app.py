import flask_login
from flask import Flask, render_template, url_for,request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user,LoginManager, login_required, logout_user,current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'danila2001'

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<Users %r>' % self.id


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    id_user = db.Column(db.Integer,db.ForeignKey('users.id'))
    deleted = db.Column(db.Integer, default=0)

    def __repr__(self):
        return '<Article %r>' % self.id_user


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=3, max=100)], render_kw={'placeholder': "username", 'class':'form-control'})
    mail = StringField(validators=[InputRequired(), Length(
        min=6, max=100)], render_kw={'placeholder': "mail", 'class':'form-control'})
    password = PasswordField(validators=[InputRequired(), Length(
        min=5, max=100,)], render_kw={'placeholder': 'password', 'class':'form-control'})

    submit = SubmitField('Зарегестрироваться')

    def validate_username(self, username):
        existing_username = Users.query.filter_by(name=username.data).first()
        if existing_username:
            raise ValidationError('That name is already exists, pls choose a different one ')

    def validate_mail(self, mail):
        existing_mail = Users.query.filter_by(name= mail.data).first()
        if existing_mail:
            raise ValidationError('That mail is already exists, pls choose a different one ')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=3, max=100)], render_kw={'placeholder': "Username", 'class':'form-control'})
    password = PasswordField(validators=[InputRequired(), Length(
        min=5, max=100, )], render_kw={'placeholder': 'password', 'class':'form-control'})

    submit = SubmitField('Войти')


@app.route('/', methods=['POST', 'GET'])
@login_required
def main_page():
    articles = Article.query.order_by(Article.date.desc()).all()

    users = [Users.query.get(article.id_user) for article in articles]
    if request.method == 'POST':
        Article.query.get(request.form.get('but')).deleted = 1
        db.session.commit()
    return render_template('index.html', articles=articles, users=users, user=current_user.is_anonymous)#user=current_user.is_anonymous проверяет залогинен ли юзер


@app.route('/reg', methods=['POST', 'GET'])
def reg():
    form = RegisterForm()
    if form.validate_on_submit():
        mail = form.mail.data
        name = form.username.data
        hash_password = bcrypt.generate_password_hash(form.password.data)
        user = Users(mail=mail, name=name, password=hash_password)

        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/')
        except:
            return 'Введены некорректные данные'
    else:
        return render_template("reg.html", form=form)


@app.route('/create-article', methods=['POST', 'GET'])
@login_required
def create_article():
    if request.method == 'POST':
        title = request.form['title']
        intro = request.form['anons']
        text = request.form['text']
        id = flask_login.current_user.get_id()
        print(id)
        article = Article(title=title, text=text, intro=intro, id_user=id)
        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/')
        except:
            return 'Ошибка русский на 55 баллов'
    else:
        return render_template('create-article.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(name=form.username.data).first()

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/')
    return render_template('login.html', form=form)


@app.route('/bin', methods=['POST', 'GET'])
@login_required
def bin_f():
    articles = Article.query.order_by(Article.date.desc()).all()
    users = [Users.query.get(article.id_user) for article in articles]
    print(current_user.id)
    if request.method == 'POST':
        Article.query.get(request.form.get('but')).deleted = 0
        db.session.commit()
        return redirect('/bin')
    return render_template('bin.html', articles=articles, users=users, user=current_user)


@app.route('/poste/<int:id>')
@login_required
def poste_detail(id):
    article = Article.query.get(id)
    return render_template('poste.html', article=article)


@app.route('/poste/<int:id>/upd', methods=['POST', 'GET'])
@login_required
def poste_upg(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.title = request.form['title']
        article.intro = request.form['intro']
        article.text = request.form['text']
        try:
            db.session.commit()
            return redirect('/')
        except:
            return "Ошибка"
    else:
        return render_template('poste_upd.html',article=article)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/prof', methods=['POST', 'GET'])
@login_required
def prof():
    change = False
    if request.method == 'POST':
        change = True
    return render_template('prof.html', user=current_user)


@app.route('/bin/<int:id>')
def poste_delete(id):
    articles = Article.query.get_or_404(id)
    try:
        db.session.delete(articles)
        db.session.commit()
        return redirect('/bin')
    except:
        return 'Ошибка'


if __name__ == '__main__':
    app.run(debug=True)