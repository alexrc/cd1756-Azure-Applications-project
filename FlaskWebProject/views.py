"""
Routes and views for the flask application.
"""

from flask import render_template, flash, redirect, request, session, url_for
from werkzeug.urls import url_parse
from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import PostForm
from flask_login import current_user, login_user, logout_user, login_required
from FlaskWebProject.models import User, Post
import uuid

imageSourceUrl = 'https://' + app.config['BLOB_ACCOUNT'] + '.blob.core.windows.net/' + app.config['BLOB_CONTAINER'] + '/'


@app.route('/')
@app.route('/home')
@login_required
def home():
    posts = Post.query.all()
    return render_template('index.html', title='Home Page', posts=posts)


@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files['image_path'], current_user.id, new=True)
        return redirect(url_for('home'))
    return render_template('post.html', title='Create Post', imageSource=imageSourceUrl, form=form)


@app.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    post = Post.query.get(int(id))
    form = PostForm(formdata=request.form, obj=post)
    if form.validate_on_submit():
        post.save_changes(form, request.files['image_path'], current_user.id)
        return redirect(url_for('home'))
    return render_template('post.html', title='Edit Post', imageSource=imageSourceUrl, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            app.logger.warning("Invalid login attempt")
            return """
                <h1>Sign In</h1>
                <p style='color:red;'>Invalid username or password</p>
                <form method="post">
                    <p><input type="text" name="username" placeholder="Username"></p>
                    <p><input type="password" name="password" placeholder="Password"></p>
                    <p><button type="submit">Sign In</button></p>
                </form>
                <h2>OR</h2>
                <p><a href="/microsoft_login">Sign in with Microsoft</a></p>
            """

        login_user(user, remember=False)
        app.logger.info(f"{user.username} logged in successfully")

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')

        return redirect(next_page)

    return """
        <h1>Sign In</h1>
        <form method="post">
            <p><input type="text" name="username" placeholder="Username"></p>
            <p><input type="password" name="password" placeholder="Password"></p>
            <p><button type="submit">Sign In</button></p>
        </form>
        <h2>OR</h2>
        <p><a href="/microsoft_login">Sign in with Microsoft</a></p>
    """


@app.route('/microsoft_login')
def microsoft_login():
    try:
        import msal

        session["state"] = str(uuid.uuid4())

        msal_app = msal.ConfidentialClientApplication(
            client_id=app.config["CLIENT_ID"],
            client_credential=app.config["CLIENT_SECRET"],
            authority=app.config["AUTHORITY"]
        )

        flow = msal_app.initiate_auth_code_flow(
            scopes=Config.SCOPE,
            state=session["state"],
            redirect_uri=url_for("authorized", _external=True)
        )

        session["flow"] = flow
        auth_url = flow.get("auth_uri")

        if not auth_url:
            flash("Microsoft login URL could not be created.")
            return redirect(url_for("login"))

        return redirect(auth_url)

    except Exception as ex:
        app.logger.exception("Microsoft login initialization failed")
        flash(f"Microsoft login initialization failed: {str(ex)}")
        return redirect(url_for("login"))


@app.route(Config.REDIRECT_PATH)
def authorized():
    try:
        import msal

        if request.args.get("state") != session.get("state"):
            flash("State mismatch. Please try signing in again.")
            return redirect(url_for("login"))

        if "error" in request.args:
            return render_template("auth_error.html", result=request.args)

        flow = session.get("flow", {})
        if not flow:
            flash("Authentication flow is missing. Please try again.")
            return redirect(url_for("login"))

        msal_app = msal.ConfidentialClientApplication(
            client_id=app.config["CLIENT_ID"],
            client_credential=app.config["CLIENT_SECRET"],
            authority=app.config["AUTHORITY"]
        )

        result = msal_app.acquire_token_by_auth_code_flow(
            flow,
            request.args
        )

        if "error" in result:
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")

        user = User.query.filter_by(username="admin").first()
        if not user:
            flash("Admin user not found.")
            return redirect(url_for("login"))

        login_user(user)
        app.logger.info("admin logged in successfully via Microsoft")

        return redirect(url_for('home'))

    except Exception as ex:
        app.logger.exception("Microsoft callback failed")
        flash(f"Microsoft callback failed: {str(ex)}")
        return redirect(url_for("login"))


@app.route('/logout')
def logout():
    logout_user()
    if session.get("user"):
        session.clear()
        return redirect(
            Config.AUTHORITY + "/oauth2/v2.0/logout"
            + "?post_logout_redirect_uri="
            + url_for("login", _external=True)
        )
    return redirect(url_for('login'))