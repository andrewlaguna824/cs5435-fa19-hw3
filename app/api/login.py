from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)

import app.api.encr_decr
from app.api.hash_table import HashTable,Entry


encryption_key = b'\x00'*16
hash_key = b'\x01'*16
htsize = 2**16
param_ht = HashTable(htsize, hash_key)

@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    for param,val in request.forms.iteritems():
        param_ht.insert(param,val)
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != password:
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            user = create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        cbc = app.api.encr_decr.Encryption(encryption_key)
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", session.get_id())
        
        # FINDME: admin bytes 0x00 (not admin) or 0x01 (admin) concatentated with plaintext password
        admin_cookie_pt = app.api.encr_decr.format_plaintext(int(user.admin), password)
        print("admin cookie plaintext: "+ str(admin_cookie_pt))
        ctxt = cbc.encrypt(admin_cookie_pt)
        response.set_cookie("admin", ctxt.hex())
        return redirect("/profile/{}".format(username))
    return template("login", login_error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")


