import siphash
import math
import random
import time

class Entry:
    def __init__(self,k=None,v=None):
        self.key = k
        self.value = v
        
    def setkey(self, k):
        self.key = k

    def setval(self, v):
        self.value = v

    def __str__(self):
        return "<"+str(self.key).rjust(11, " ")+","+str(self.value).rjust(7, " ")+">"


class HashBucket:
    entries = []
    def __init__(self, _entries=None):
        if not _entries is None:
            self.entries = _entries


    def get_size(self):
        return len(self.entries)
            
    def contains_key(self, k):
        retval = -1
        for curr_entry_index in range(len(self.entries)):
            if self.entries[curr_entry_index].key == k:
                retval = curr_entry_index
        return retval
            
    def add_entry(self, e):
        #Check if an entry with this key is already in the bucket
        ind = self.contains_key(e.key)
        if ind >= 0:
            self.entries[ind].value = e.value
            return True
        #If we get here, we know no entry with exactly this key is
        #in the bucket, so we need to find the place to insert the new key-value pair.
        is_set = False
        index = 0
        for curr_index in range(len(self.entries)):
            #The first time we see something bigger than
            #the current key, mark the index.
            if self.entries[curr_index].key > e.key and not is_set:
                index = curr_index
                is_set = True

        new_entries = [Entry() for i in range(len(self.entries)+1)]
        #print("index: "+str(index))
        for curr_index in range(len(new_entries)):
            if curr_index < index:
                new_entries[curr_index].key = self.entries[curr_index].key
                new_entries[curr_index].value = self.entries[curr_index].value
            elif curr_index == index:
                new_entries[curr_index].key = e.key
                new_entries[curr_index].value = e.value
            else:
                new_entries[curr_index].key = self.entries[curr_index-1].key
                new_entries[curr_index].value = self.entries[curr_index-1].value

        self.entries = new_entries
        return True

    def get_value_if_in_bucket(self, k):
        ind = self.contains_key(k)
        if ind < 0:
            return None
        else:
            return self.entries[ind].value
    
# A closed-addressing hash table with collision resolution via chaining.
class HashTable:
    default_tkey = b'\x00'*16
    
    def __init__(self,htsize,hash_table_key=None):
        self.size = htsize
        self.table = [HashBucket() for i in range(htsize)]
        self.tkey = HashTable.default_tkey
        self.occupied = 0

    # Returns the siphash of the input with the hash table's key.
    def get_hash(self, to_hash):
        return siphash.SipHash_2_4(self.tkey, to_hash).hash()

    # Inserts the pair <e.key, e.value> into the hash table.
    # If some record with e.key already exists, set its value to e.value.
    # Otherwise create a new entry with key e.key and value e.value.
    # Returns True if the operation succeeded.
    def insert_entry(self, e,print_loads=False):
        assert not (e.key is None or e.value is None)
        print("Hash key: {}".format(self.tkey))
        print("Calling insert for key-value pair: " + str(e))
        entry_hval = self.get_hash(e.key)
        print("hash value is: " + str(entry_hval))
        table_index = entry_hval % self.size
        print("Table index: {}".format(table_index))
        if print_loads:
            print("Bucket loads:" + str(list(self.table[x].get_size() for x in range(self.size))))
        return self.table[table_index].add_entry(e)
    
    def insert(self, ikey, ivalue):
        assert isinstance(ikey, str)
        return self.insert_entry(Entry(ikey.encode("utf8"),ivalue))

    # If a pair with key 'key_to_delete' exists, remove it from the hash table.
    # Else, do nothing. Returns True if the operation succeeded.
    def delete(self, key_to_delete):
        assert not key_to_delete is None
        print("Calling delete for key: " + str(key_to_delete))
        raise Exception("We're not implementing delete right now.")
    
    # If a pair with key 'key_to_read' exists, locate it and return its value.
    # Returns the value associated to key_to_read, and False if no such value exists.
    def read(self, key_to_read):
        assert not key_to_read is None
        print("Calling read for key: " + str(key_to_read))
        entry_hval = self.get_hash(key_to_read)
        print("hash value is: " + str(entry_hval))
        table_index_orig = entry_hval % self.size
        return self.table[table_index_orig].get_value_if_in_bucket(key_to_read)

    




