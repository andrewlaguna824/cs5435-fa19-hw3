from bottle import (
    post,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import (
    get_user,
)

from app.models.session import (
    logged_in,
)

import app.api.encr_decr

encryption_key = b'\x00'*16

@post('/setcoins')
@logged_in
def set_coins(db, session):
    admin = get_user(db, session.get_username())
    ctxt = request.get_cookie("admin")
    print("admin cookie hex: " + ctxt)
    ctxt_bytes = bytes.fromhex(ctxt)
    cbc = app.api.encr_decr.Encryption(encryption_key)
    try:
        dpt = cbc.decrypt(ctxt_bytes)
    except ValueError as exc:
        return template(
                "profile",
                user=admin,
                session_user=admin,
                error="Unspecified error.",
                admin=admin.admin,
                )
    # FINDME: Decrypt returns False if there was a padding exception
    # Response is 200 OK even if admin flag check fails
    if not dpt:
        print("FINDME: bad padding for admin cookie")
        return template(
                "profile",
                user=admin,
                session_user=admin,
                error="Bad padding for admin cookie!",
                admin=admin.admin,
                )
    is_admin_user = app.api.encr_decr.is_admin_cookie(dpt)
    print("********************************************")
    print("FINDME: Is admin user: " + str(is_admin_user))
    print("********************************************")
    if not is_admin_user:
        # response.status = 400
        return template(
            "profile",
            user=admin,
            session_user=admin,
            error="Missing admin privilege.",
            admin=False,
        )
    target_user = get_user(db, request.forms.get('username'))
    amount = int(request.forms.get('amount'))
    error = None
    if (amount < 0):
        response.status = 400
        error = "Amount cannot be negative."
    elif (target_user is None):
        response.status = 400
        error = "Target user {} does not exist.".format(request.forms.get('username'))
    else:
        target_user.set_coins(amount)
    return template(
        "profile",
        user=admin,
        session_user=admin,
        admin=admin.admin,
        admin_error=error,
    )

