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
    max_len = 0
    while max_len < total_collisions:
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        hash_value = ht_hash(key, rand_str.encode('utf-8'), 2**16)
        if hash_value in collisions:
            collisions[hash_value].append(rand_str)
            curr_bucket_len = len(collisions[hash_value])
            if (curr_bucket_len > max_len):
                print("A bucket reached " + str(curr_bucket_len) 
                    + " colliding strings (program stops at " + str(total_collisions) + ")")
                max_len = curr_bucket_len
            if curr_bucket_len >= total_collisions:
                return collisions[hash_value]
        else:
            collisions[hash_value] = [rand_str]

#Implement this function, which takes the list of
#collisions and verifies they all have the same
#SipHash output under the given key.
def check_collisions(key, colls):
    identical_bucket = ht_hash(key, colls[0].encode('utf-8'), 2**16)

    for string in colls:
        curr_bucket = ht_hash(key, string.encode('utf-8'), 2**16)
        if curr_bucket != identical_bucket:
            # collision not matching, return false
            return False

    # all have the same hash
    return True

if __name__=='__main__':
    #Look in the source code of the app to
    #find the key used for hashing.
    key = b'\x00'*16
    
    # in this case we find 20 collisions
    colls = find_collisions(key, 20)
    print("Collisions:", colls)

    # verify if collisions hash to same bucket
    if (check_collisions(key, colls)):
        # all collisions go to same bucket
        print("All collisions hash to same bucket")
    else:
        print("ERROR: collisions DO NOT hash to same bucket")
