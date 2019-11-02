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
    # print("STring encoded: {}".format(s.encode('utf-8')))
    h = ht_hash(key, s.encode('utf-8'), ht_size)
    print("Hash: {}".format(h))
    s = "test1" 
    h = ht_hash(key, s.encode('utf-8'), ht_size)
    print("Hash: {}".format(h))

    # ascii = b''.join([chr(i) for i in range(33, 127)])

    # try to find matching hashes for "test"
    letters = string.ascii_lowercase
    print("Checking matching hashes for string '{}'; hash '{}'".format(s, h))
    colliding_strings = {}
    colliding_strings[s] = True
    # for i in range(500000):
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
 
    # found = {}
    # letters = string.ascii_lowercase
    # matches = []
    # for i in range(5000):
    #      # Build random 4 byte random string
    #      # s = b''.join([random.choice(ascii) for _ in range(4)])
    #      # print("Random string: {}".format(s))
    #      s = ''.join(random.choice(letters) for i in range(4))
    #      # print("Random string: {}".format(s))

    #      # Calculate hash
    #      h = ht_hash(key, s.encode('utf-8'), ht_size)
    #      print("Hash: {}".format(h))
    #      if h in found:
    #          v = found[h]
    #          if v == s:
    #              print("Same hash and same string")
    #              continue
    #          else:
    #              print("Found two colliding hashes: {} == {}; Hash: {}".format(v, s, h))
    #              # Add to list of matches
    #      else:
    #          found[h] = s

# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.
def check_collisions(key, colls):
    pass

if __name__=='__main__':
    # Look in the source code of the app to
    # find the key used for hashing.
    ht_size = 2**16 # TODO: Hardcoded
    hash_key = b'\x01'*16
    colls = find_collisions(hash_key, ht_size, 20)

    print("Collisions: {}".format(colls))
