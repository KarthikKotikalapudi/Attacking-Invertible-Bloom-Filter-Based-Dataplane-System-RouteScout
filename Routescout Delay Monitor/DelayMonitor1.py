import hashlib,math,struct,time
import mmh3
from struct import pack,unpack

def fxor(a, b):
    rtrn = []
    a = struct.pack('d', a)
    b = struct.pack('d', b)
    for ba, bb in zip(a, b):
        rtrn.append(ba ^ bb)
    return struct.unpack('d', bytes(rtrn))[0]  
    

def make_hashfuncs(num_slices, num_cells,key):
    
    seeds= [i for i in range(1,num_slices+1)]
    rval = []
    rval.extend(int(abs(mmh3.hash(key, seed))%num_cells) for seed in seeds)
        
    return rval
    
    
class IBLT(object):
    
    def _init_(self,capacity,error_rate=0.001,kc=9):
        self.capacity=capacity
        self.kc=kc
        
        self.ct_size = int((self.kc * self.capacity)/math.log(2))
        #print(self.ct_size)
        self.cells_per_slice = int(self.ct_size/self.kc)
        #print(self.cells_per_slice)
        self.accumulator = []
        self.counter = []
        for i in range(self.ct_size):
            self.accumulator.append(0.00)
            self.counter.append(0)
           
    def _contains_(self,key):
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            if self.counter[offset+k] < 1:
                return False
            offset+=self.cells_per_slice
            return True
            
            
    def _insert_(self,key,ts):
        
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        #print(hashes)
        
        offset = 0
        #print(ts)
        #PresTime = time.time()*1000
        for k in hashes:
            self.accumulator[k+offset] = fxor(self.accumulator[k+offset] , ts)
            #print(self.accumulator[k+offset])
            self.counter[k+offset] = self.counter[k+offset] + 1
            #print(self.counter[k+offset])
            
            #print(self.counter[k+offset])
            offset += self.cells_per_slice
        #print('                   ')
    
    #To get collisions
    def _get_collisions_(self, key):
        hashes = make_hashfuncs(self.kc, self.cells_per_slice, key)
        offset = 0
        count = 0
        for k in hashes:
            if self.counter[k + offset] >= 1:
                count += 1
            offset += self.cells_per_slice
        return count    

    def _get_pure_cell_(self, key):
        hashes = make_hashfuncs(self.kc, self.cells_per_slice, key)
        offset = 0
        count = 0
        for k in hashes:
            if self.counter[k + offset] == 1:
                count += 1
            offset += self.cells_per_slice
        return count           
            
    def _get_ts_(self,key):
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            #print(self.counter[offset+k])
            if self.counter[offset+k] == 1:
                return offset+k
            offset += self.cells_per_slice

        return -1
            
    def _delete_(self,key,ts):
        
        hashes=make_hashfuncs(self.kc,self.cells_per_slice,key)
        #print(hashes)
        offset = 0

        ind = self._get_ts_(key)
        if ind == -1:
            return -1
        
        timeStamp = self.accumulator[ind]
        
        
            
        for k in hashes:
            self.accumulator[k+offset] = fxor(self.accumulator[k+offset] , timeStamp)
            self.counter[k+offset] = self.counter[k+offset] - 1
            #print(self.counter[k+offset])
            offset += self.cells_per_slice
        # if ts-timeStamp > 1:
        #     print(ts-timeStamp)
        #     print(timeStamp)

        return abs(ts - timeStamp)
            

    def _error_rate_(self):
        k = 9
        n=self.capacity
        m = self.ct_size
        a = 1 - math.pow(math.e,-k*n/m)
        return math.pow(a,k)
    
    #added
    def reset(self):
        sze = len(self.accumulator)
        self.accumulator = [0] * sze
        self.counter = [0] * sze
