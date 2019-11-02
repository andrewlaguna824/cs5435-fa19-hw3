from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"

#This function will send the login form
#with the colliding parameters you specify.
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
    uname =""
    pw = ""

    # Put your colliding inputs in this dictionary as parameters.
    attack_dict = {}
    response = do_login_form(sess, uname, pw, attack_dict)


if __name__=='__main__':
    do_attack()
