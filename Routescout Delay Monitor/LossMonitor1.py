
from scapy.all import *
import mmh3

import math
import random

def make_hashfuncs(num_slices, num_bits,key): #this function returns a list of index values after doing hashing
                                              #Note: we are dividing the BF into chunks , for each chunk we return the hash index
  
    seeds= [i for i in range(1,num_slices+1)]
    rval = []
    rval.extend(int(abs(mmh3.hash(key,seed))%num_bits) for seed in seeds) 

    del rval[num_slices:]
    return rval

# This class has all the functionalities of the Loss Monitor
# Loss Monitor Consists of Counting Bloom Filter and Loss Aggregator to count the lost and expected packets  

class LossMonitor(object):
    def __init__(self, capacity, error_rate=0.001, kl=3):                #function to intiailise the data structures of the Delay Monitor

        self.capacity=capacity
        self.kl=kl
        if not (0 < error_rate < 1):
            raise ValueError("Error_Rate must be between 0 and 1.")
        if not capacity > 0:
            raise ValueError("Capacity must be > 0")
        self.lm_size=int((self.kl * self.capacity)/math.log(2))   #counting bloom filter size is calculated with this formula (taken from the paper 'evil choices of bloom flter')

        self.cells_per_slice = int(self.lm_size/self.kl)           # we are dividing the datastructure into chunks 
        self.count_min_sketch=[]


        for i in range(self.lm_size):                               #initialising the data structure with 0
            self.count_min_sketch.append(0)

    def contains(self,key):
        
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            if self.count_min_sketch[offset+k] < 1:
                return False
            offset+=self.cells_per_slice
            return True

    def insert(self,key):                      # this function is used to insert the next expected packet of the sequence (note: next expected packet not the current one)
                
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0

        for k in hashes:
            self.count_min_sketch[k+offset] = self.count_min_sketch[k+offset] + 1   # we are incrementing the counter by 1 to insert the next expected packet
            offset += self.cells_per_slice

 
    def verify_expectation(self,key):      #function to check if the packet (key) is expected or not 
        
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
  
        offset = 0
        result=[]
                                                #verification is done by checking if all the values at the corresponding indices are greater than 0
        for k in hashes:
            result.append(self.count_min_sketch[offset+k])
            offset+=self.cells_per_slice
        
        for i in range(len(result)):
            if result[i] < 1:
                return False
            
        return True

    def delete(self,key):                               #function to clean the CBF                             
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0
        for k in hashes:
            self.count_min_sketch[k+offset] = self.count_min_sketch[k+offset] - 1            #counters are decremented by 1 at the corresponding hash indices
            offset += self.cells_per_slice
            # if k+offset < self.lm_size:
            #     print(self.count_min_sketch[k+offset])



