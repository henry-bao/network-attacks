import siphash
import string
import random

def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

#Put your collision-finding code here.
#Your function should output the colliding strings in a list.
def find_collisions(key, total_collisions):
    collisions = {}
    attempts = 0
    while True:
        l = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        hash_value = ht_hash(key, l.encode('utf-8'), 2**16)
        if hash_value in collisions:
            collisions[hash_value].append(l)
            if len(collisions[hash_value]) >= total_collisions:
                return collisions[hash_value]
        else:
            collisions[hash_value] = [l]
        attempts += 1
        if attempts % 100000 == 0:
            print(f"Attempted {attempts} strings.")

#Implement this function, which takes the list of
#collisions and verifies they all have the same
#SipHash output under the given key.
def check_collisions(key, colls):
    expected_hash = ht_hash(key, colls[0].encode('utf-8'), 2**16)
    return all(ht_hash(key, l.encode('utf-8'), 2**16) == expected_hash for l in colls)

if __name__=='__main__':
    #Look in the source code of the app to
    #find the key used for hashing.
    key = b'\x00'*16
    
    # in this case we find 20 collisions
    colls = find_collisions(key, 20)
    print("Collisions:", colls)
    print("Do all collisions hash to the same value?", "Yes" if check_collisions(key, colls) else "No")
