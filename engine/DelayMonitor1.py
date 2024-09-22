import hashlib,math,struct,time
import mmh3
from struct import pack,unpack

def fxor(a, b):                                           #function performs a XOR b and returns the result , taken from gfg
    rtrn = []
    a = struct.pack('d', a)
    b = struct.pack('d', b)
    for ba, bb in zip(a, b):
        rtrn.append(ba ^ bb)
    return struct.unpack('d', bytes(rtrn))[0]  
    

def make_hashfuncs(num_slices, num_cells,key):      #this function returns a list of index values after doing hashing
                                                    #Note: we are dividing the BF into chunks , for each chunk we return the hash index
    
    seeds= [i for i in range(1,num_slices+1)]
    rval = []
    rval.extend(int(abs(mmh3.hash(key, seed))%num_cells) for seed in seeds)        #we use mmh3 hash function 
        
    return rval
    
# This class has all the functionalities of the Delay Monitor
# Delay Monitor Consists of Inverted Bloom look up Table for and Counting Bloom Filter for maintaining count of number of delays  
# Delay monitor has Delay aggregator to calculate sum of delays and number of delays
class DelayMonitor(object):
    
    def _init_(self,capacity,error_rate=0.001,kc=9):  #function to intiailise the data structures of the Delay Monitor
        self.capacity=capacity
        self.kc=kc
        
        self.ct_size = int((self.kc * self.capacity)/math.log(2))  #counting bloom filter size is calculated with this formula (taken from the paper 'evil choices of bloom flter')
        self.cells_per_slice = int(self.ct_size/self.kc)       # we are dividing the datastructure into chunks 
        self.accumulator = []
        self.counter = []
        self.aggregator = []
        for i in range(self.ct_size):                           #initialising the data structures with 0 
            self.accumulator.append(0.00)
            self.counter.append(0)
           
    def _contains_(self,key):       #function to check if key is present in the CBF
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)    #hashes is a list of hash indices
        offset = 0
        #if all the values at the corresponding hash indices are greater than 0 , then we say the key is present. This is what is being checked in the below for loop
        for k in hashes:
            if self.counter[offset+k] < 1:
                return False
            offset+=self.cells_per_slice
        return True
        
#this below function is used afterwards for chosen insertion adversary attack 
    def _check_for_non_collision_(self,key):
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)    #hashes is a list of hash indices
        offset = 0
        #if all the values at the corresponding hash indices are 0 , then we say the key is non present. This is what is being checked in the below for loop
        for k in hashes:
            if self.counter[offset+k] > 0 or self.counter[offset+k] < 0:
                return False
            offset+=self.cells_per_slice
        return True
    
#this below function is used for query only adversary attack 
    def _check_for_pure_cell_(self,key):
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)    #hashes is a list of hash indices
        offset = 0
        #if all the values at the corresponding hash indices are 0 , then we say the key is non present. This is what is being checked in the below for loop
        for k in hashes:
            if self.counter[offset+k] == 1:
                return True
            offset+=self.cells_per_slice
        return False
    
            
    def _insert_(self,key,ts):        #function for performing insertion into the Delay Monitor
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        
        offset = 0

        for k in hashes:
            self.accumulator[k+offset] = fxor(self.accumulator[k+offset] , ts)    #timestamp is appended in the IBLT at the respective indices after hashing
            self.counter[k+offset] = self.counter[k+offset] + 1                   #counter is incremented by in the CBF for maintaining number of Delays
            
            offset += self.cells_per_slice

            
            
    def _get_ts_(self,key):                                       # function returns the index of the pure cell in IBLT if present else returns -1
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            if self.counter[offset+k] == 1:
                return offset+k
            offset += self.cells_per_slice

        return -1
            
    def _delete_(self,key,ts):                                   # this function cleans the data structure and based on the purecell returns the time stamp for the key
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        offset = 0
        index=self._get_ts_(key)
        if index==-1:
            return -1
        
        else:
            timeStamp = self.accumulator[index]           #based on the purecell we get the timestamp
            
        for k in hashes:                                           #based on the timestamp the follwoing for loop cleans the datastructures by performing XOR at the indices , counter is also reduced by 1 continuosly
            self.accumulator[k+offset] = fxor(self.accumulator[k+offset] , timeStamp)
            self.counter[k+offset] = self.counter[k+offset] - 1
            offset += self.cells_per_slice                   

        return ts - timeStamp  # This difference gives the DELAY we want to calculate
            

    def _error_rate_(self):                             #function to calculate FPR , formula taken from the paper 'The evil choices of Bloom Filter' 
        k = 9
        n=self.capacity
        m = self.ct_size
        a = 1 - math.pow(math.e,-k*n/m)
        return math.pow(a,k)
