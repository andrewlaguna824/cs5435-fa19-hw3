import siphash
import random
import string

def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

# Put your collision-finding code here.
# Your function should output the colliding strings in a list.
def find_collisions(key, ht_size, num_collisions):
    s = "test" 
    h = ht_hash(key, s.encode('utf-8'), ht_size)

    # try to find matching hashes for "test"
    letters = string.ascii_lowercase
    print("Checking matching hashes for string '{}'; hash '{}'".format(s, h))
    colliding_strings = {}
    colliding_strings[s] = True
    while len(colliding_strings) < num_collisions:
        # Build random 4 byte strings
        s_random = ''.join(random.choice(letters) for i in range(8))
       
        # Calculate hash
        h_test = ht_hash(key, s_random.encode('utf-8'), ht_size)
     
        # Check if the hash matches ours
        if h_test == h:
            if s_random not in colliding_strings:
                print("Found two colliding hashes: {} == {}; Hash: {}".format(s, s_random, h))
                colliding_strings[s_random] = True

    return list(colliding_strings.keys())
 
# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.
def check_collisions(key, ht_size, colls):
    h = ht_hash(key, colls[0].encode('utf-8'), ht_size)
    for c in colls:
        h_test = ht_hash(key, c.encode('utf-8'), ht_size)
        if h_test != h:
            return False       
    return True

if __name__=='__main__':
    # Look in the source code of the app to
    # find the key used for hashing.
    ht_size = 2**16
    hash_key = b'\x00'*16
    colls = find_collisions(hash_key, ht_size, 10)

    print("Collisions: {}".format(colls))

    print(check_collisions(hash_key, ht_size, colls))
