"""
Routes and views for the flask application.
"""

from flask import render_template, flash, redirect, request, session, url_for
from werkzeug.urls import url_parse
from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import current_user, login_user, logout_user, login_required
from FlaskWebProject.models import User, Post
import msal
import uuid

imageSourceUrl = 'https://' + app.config['BLOB_ACCOUNT'] + '.blob.core.windows.net/' + app.config['BLOB_CONTAINER'] + '/'


@app.route('/')
@app.route('/home')
@login_required
def home():
    posts = Post.query.all()
    return render_template(
        'index.html',
        title='Home Page',
        posts=posts
    )


@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files['image_path'], current_user.id, new=True)
        return redirect(url_for('home'))
    return render_template(
        'post.html',
        title='Create Post',
        imageSource=imageSourceUrl,
        form=form
    )


@app.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    post = Post.query.get(int(id))
    form = PostForm(formdata=request.form, obj=post)
    if form.validate_on_submit():
        post.save_changes(form, request.files['image_path'], current_user.id)
        return redirect(url_for('home'))
    return render_template(
        'post.html',
        title='Edit Post',
        imageSource=imageSourceUrl,
        form=form
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    # Login tradicional
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            app.logger.warning("Invalid login attempt")
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)
        app.logger.info(f"{user.username} logged in successfully")

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')
        return redirect(next_page)

    # Login Microsoft
    session["state"] = str(uuid.uuid4())

    msal_app = _build_msal_app()
    auth_url = None
    if msal_app:
        auth_url = msal_app.get_authorization_request_url(
            scopes=Config.SCOPE,
            state=session["state"],
            redirect_uri=url_for("authorized", _external=True)
        )

    if not auth_url:
        app.logger.error("Microsoft login URL could not be created.")
        auth_url = "#"

    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)


@app.route(Config.REDIRECT_PATH)
def authorized():
    # Se usuário cancelou ou houve erro da Microsoft
    if "error" in request.args:
        app.logger.warning(f"Microsoft login failed: {request.args}")
        return render_template("auth_error.html", result=request.args)

    # Valida estado
    if request.args.get("state") != session.get("state"):
        app.logger.warning("Microsoft login state mismatch")
        flash("State mismatch. Please try again.")
        return redirect(url_for("login"))

    code = request.args.get("code")
    if not code:
        app.logger.warning("Microsoft login returned no authorization code")
        flash("No authorization code was returned.")
        return redirect(url_for("login"))

    msal_app = _build_msal_app()
    if not msal_app:
        app.logger.error("MSAL app could not be created")
        flash("Microsoft sign-in is not configured correctly.")
