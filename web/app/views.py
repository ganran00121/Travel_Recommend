from flask import (jsonify, render_template,
                   request, url_for, flash, redirect , Flask, session)
import json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
import os

from app import app
from app import db
from app import login_manager

from app.models.contact import Contact
from app.models.BlogEntry import BlogEntry
from app.models.authuser import AuthUser, PrivateContact , PrivateBlogEntry



# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='543451996387-hmpmrvok2d781vfpq9eis8m0rij1durp.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

@app.route('/')
def hello_world():
    return 'Hello, you are logge in as!'

@app.route('/login')
def login():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google') 
    token = google.authorize_access_token()
    resp = google.get('userinfo') 
    user_info = resp.json()
    #{'email': 'ganran00121@gmail.com', 
    # 'given_name': 'GEMP', 
    # 'id': '115465582601124357792',
    #  'locale': 'th', 
    # 'name': 'GEMP', 
    # 'picture': 'https://lh3.googleusercontent.com/a/AGNmyxZWHSuuFS0txPaj7LqYRwwgPZ4OhKi6xYFo9QE6Kg=s96-c', 
    # 'verified_email': True}
    email = user_info['email']
    name = user_info['name']
    password = " "
    avatar_url = user_info['picture']    

    user_check = AuthUser.query.filter_by(email=user_info['email']).first()
    
    if  user_check :
        login_user(user_check)
    else :
        new_user = AuthUser(email = email, 
                            name = name,
                            password = "   ",
                            avatar_url = avatar_url)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    return redirect(url_for('lab12_index'))

@login_manager.user_loader
def load_user(user_id):
    return AuthUser.query.get(int(user_id))

@app.route('/crash')
def crash():
    return 1/0


@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)





@app.route("/lab11/BlogEntry")
@login_required
def lab11_db_BlogEntry():
    db_contacts = PrivateBlogEntry.query.filter(
        PrivateBlogEntry.owner_id == current_user.id)
    contacts = list(map(lambda x: x.to_dict(), db_contacts))
    app.logger.debug("DB Contacts: " + str(contacts))

    return jsonify(contacts)

@app.route("/lab11/BlogEntry/all")
def lab11_db_BlogEntry_all():
    contacts = []
    db_contacts = BlogEntry.query.all()

    contacts = list(map(lambda x: x.to_dict(), db_contacts))
    app.logger.debug("DB Contacts: " + str(db_contacts))

    return jsonify(contacts)

@app.route("/lab12/authuser/PrivateBlogEntry")
def lab12_db_PrivateBlogEntry_all():
    contacts = []
    db_contacts = PrivateBlogEntry.query.all()

    contacts = list(map(lambda x: x.to_dict(), db_contacts))
    app.logger.debug("DB Contacts: " + str(db_contacts))

    return jsonify(contacts)

@app.route("/lab12/authuser/AuthUser")
def lab12_db_authuser_all():
    contacts = []
    db_contacts = AuthUser.query.all()

    contacts = list(map(lambda x: x.to_dict(), db_contacts))
    app.logger.debug("DB Contacts: " + str(db_contacts))


    return jsonify(contacts)


@app.route('/lab11/remove_BlogEntry', methods=('GET', 'POST'))
def lab11_remove_BlogEntry():
    app.logger.debug("LAB11 - REMOVE")
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        try:
            contact = BlogEntry.query.get(id_)
            db.session.delete(contact)
            db.session.commit()
        except Exception as ex:
            app.logger.debug(ex)
            raise
    return lab11_db_BlogEntry()
    
@app.route("/lab11", methods=('GET', 'POST'))
def lab11():
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
        id_ = result.get('id', '')
        validated = True
        validated_dict = dict()
        valid_keys = ['name', 'message', 'email','date_created']

        # validate the input
        for key in result:
            app.logger.debug(key, result[key])
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value

        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            # if there is no id_: create contact
            if not id_:
                validated_dict['owner_id'] = current_user.id
                # entry = Contact(**validated_dict)
                entry = PrivateBlogEntry(**validated_dict)
                app.logger.debug(str(entry))
                db.session.add(entry)
            # if there is an id_ already: update contact
            else:
                # contact = Contact.query.get(id_)
                contact = PrivateBlogEntry.query.get(id_)
                if contact.owner_id == current_user.id:
                    contact.update(**validated_dict)


            db.session.commit()

        return lab11_db_BlogEntry()
    return render_template('lab11_microblog.html')

@app.route('/lab12')
def lab12_index():
   return redirect(url_for('lab11'))




@app.route('/lab12/profile')
@login_required
def lab12_profile():
    return render_template('lab12/profile.html')


@app.route('/lab12/confrim', methods=('GET', 'POST'))
def lab12_confrim():
    if request.method == 'POST':
        # login code goes here
        email = current_user.email
        password = request.form.get('password')

        user = AuthUser.query.filter_by(email=email).first()
 
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the
        # hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('lab12_confrim'))


        # if the above check passes, then we know the user has the right
        # credentials
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('lab12_change')
        return redirect(next_page)


    return render_template('lab12/confrim.html')

@app.route('/lab12/change', methods=('GET', 'POST'))
def lab12_change():
    if request.method == 'POST':
        # login code goes here
        email = request.form.get('email')
        name = request.form.get('name')

        user = AuthUser.query.filter_by(email=email).first()
 
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the
        # hashed password in the database
        if  user :
            if email == current_user.email :
                user = AuthUser.query.get(current_user.id)
                user.email = email
                user.name = name
                avatar_url = gen_avatar_url(email, name)
                user.avatar_url = avatar_url
                    # if the above check passes, then we know the user has the right
                    # credentials
                db.session.commit()
                next_page = url_for('lab12_finish_change')
            else :
                flash('This email has already been used. Please change your Email again.')
                # if the user doesn't exist or password is wrong, reload the page
                return redirect(url_for('lab12_change'))


        user = AuthUser.query.get(current_user.id)
        user.email = email
        user.name = name
        avatar_url = gen_avatar_url(email, name)
        user.avatar_url = avatar_url
        # if the above check passes, then we know the user has the right
        # credentials
        db.session.commit()
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('lab12_finish_change')
        return redirect(next_page)
    
    return render_template('lab12/change.html')

@app.route('/lab12/finish_change', methods=('GET', 'POST'))
def lab12_finish_change():
    
    return render_template('lab12/finish_change.html')


@app.route('/lab12/login', methods=('GET', 'POST'))
def lab12_login():
    if request.method == 'POST':
        # login code goes here
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))


        user = AuthUser.query.filter_by(email=email).first()
 
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the
        # hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('lab12_login'))


        # if the above check passes, then we know the user has the right
        # credentials
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('lab11')

        return redirect(next_page)

    return render_template('lab12/login.html')





@app.route('/lab12/signup', methods=('GET', 'POST'))
def lab12_signup():


    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
 
        validated = True
        validated_dict = {}
        valid_keys = ['email', 'name', 'password']


        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue


            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")

        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            name = validated_dict['name']
            password = validated_dict['password']
            # if this returns a user, then the email already exists in database
            user = AuthUser.query.filter_by(email=email).first()


            if user:
                # if a user is found, we want to redirect back to signup
                # page so user can try again
                flash('Email address already exists')
                return redirect(url_for('lab12_signup'))


            # create a new user with the form data. Hash the password so
            # the plaintext version isn't saved.
            app.logger.debug("preparing to add")
            avatar_url = gen_avatar_url(email, name)
            new_user = AuthUser(email=email, name=name,
                                password=generate_password_hash(
                                    password, method='sha256'),
                                avatar_url=avatar_url)
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

        return redirect(url_for('lab11'))
    return render_template('lab12/signup.html')




def gen_avatar_url(email, name):
    bgcolor = generate_password_hash(email, method='sha256')[-6:]
    color = hex(int('0xffffff', 0) -
                int('0x'+bgcolor, 0)).replace('0x', '')
    lname = ''
    temp = name.split()
    fname = temp[0][0]
    if len(temp) > 1:
        lname = temp[1][0]


    avatar_url = "https://ui-avatars.com/api/?name=" + \
        fname + "+" + lname + "&background=" + \
        bgcolor + "&color=" + color
    return avatar_url


@app.route('/lab12/logout')
@login_required
def lab12_logout():
    logout_user()
    return redirect(url_for('lab12_index'))
    
