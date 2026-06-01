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

    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    if not auth_url:
        app.logger.error("Microsoft login URL could not be created")
        auth_url = "#"

    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)


@app.route(Config.REDIRECT_PATH)
def authorized():
    if request.args.get("state") != session.get("state"):
        app.logger.warning("State mismatch in Microsoft login")
        flash("State mismatch. Please try signing in again.")
        return redirect(url_for("login"))

    if "error" in request.args:
        app.logger.warning(f"Microsoft login failed: {request.args}")
        return render_template("auth_error.html", result=request.args)

    if request.args.get("code"):
        result = _build_msal_app().acquire_token_by_auth_code_flow(
            session.get("flow", {}),
            request.args
        )

        if "error" in result:
            app.logger.warning(f"Token acquisition failed: {result}")
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")

        # Regra do projeto: qualquer login Microsoft entra como admin
        user = User.query.filter_by(username="admin").first()
        if not user:
            app.logger.error("Admin user not found")
            flash("Admin user not found.")
            return redirect(url_for("login"))

        login_user(user)
        app.logger.info("admin logged in successfully via Microsoft")

    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    logout_user()
    if session.get("user"):
        session.clear()
        return redirect(
            Config.AUTHORITY + "/oauth2/v2.0/logout" +
            "?post_logout_redirect_uri=" + url_for("login", _external=True)
        )
    return redirect(url_for('login'))


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app.config["CLIENT_ID"],
        authority=authority or Config.AUTHORITY,
        client_credential=app.config["CLIENT_SECRET"]
    )


def _build_auth_url(authority=None, scopes=None, state=None):
    flow = _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes=scopes or [],
        state=state,
        redirect_uri=url_for("authorized", _external=True)
    )
    session["flow"] = flow
    return flow.get("auth_uri")