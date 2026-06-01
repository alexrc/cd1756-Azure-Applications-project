"""
Routes and views for the flask application.
"""

from datetime import datetime
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
    user = User.query.filter_by(username=current_user.username).first_or_404()
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

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')

        return redirect(next_page)

    # login com Microsoft
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])

    # evita quebrar a página se a URL não for gerada
    if not auth_url:
        flash("Microsoft login could not be initialized.")
        auth_url = "#"

    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)


@app.route(Config.REDIRECT_PATH)
def authorized():
    flow = session.get("flow", {})

    if not flow:
        flash("Microsoft sign-in flow is missing. Please try again.")
        return redirect(url_for("login"))

    if request.args.get("state") != session.get("state"):
        flash("State mismatch. Please try again.")
        return redirect(url_for("login"))

    if "error" in request.args:
        return render_template("auth_error.html", result=request.args)

    cache = _load_cache()

    result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
        flow,
        request.args
    )

    if "error" in result:
        return render_template("auth_error.html", result=result)

    session["user"] = result.get("id_token_claims")

    # regra do projeto: login Microsoft entra como admin
    user = User.query.filter_by(username="admin").first()
    login_user(user)

    _save_cache(cache)

    return redirect(url_for('home'))


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache and cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    client_id = app.config.get("CLIENT_ID") or Config.CLIENT_ID
    client_secret = app.config.get("CLIENT_SECRET") or Config.CLIENT_SECRET
    authority = authority or app.config.get("AUTHORITY") or Config.AUTHORITY

    if not client_id or not client_secret or not authority:
        return None

    return msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority,
        token_cache=cache
    )


def _build_auth_url(authority=None, scopes=None, state=None):
    msal_app = _build_msal_app(authority=authority)
    if not msal_app:
        return None

    flow = msal_app.initiate_auth_code_flow(
        scopes=scopes or [],
        state=state,
        redirect_uri=url_for("authorized", _external=True)
    )

    session["flow"] = flow
    return flow.get("auth_uri")


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
