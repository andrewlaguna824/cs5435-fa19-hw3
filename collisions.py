import siphash

def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

#Put your collision-finding code here.
#Your function should output the colliding strings in a list.
def find_collisions(key, num_collisions):
    pass

#Implement this function, which takes the list of
#collisions and verifies they all have the same
#SipHash output under the given key.
def check_collisions(key, colls):
    pass

if __name__=='__main__':
    #Look in the source code of the app to
    #find the key used for hashing.
    ht_size = 2**16 # TODO: Hardcoded
    hash_key = b'\x01'*16
    colls = find_collisions(hash_key, 20)
