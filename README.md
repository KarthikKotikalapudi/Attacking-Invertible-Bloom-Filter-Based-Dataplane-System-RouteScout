# Secinfra-RouteScout
Code for RouteScout implementation and attack.


# ROUTESCOUT (Under construction. Will be updated soon)

This folder has 5 subfolders:
* 24kflows_caida
* 24kflows_wis
* 50kflows_caida
* 50kflows_wis
* engine

Implementation for routscout is present in the engine folder. We have also included some pcap files to test the code.

**TO RUN THE CODE**

Downlaod the RoutScout folder locally (inclduing the pcap files). Open terminal and Go to engine folder. Run main.py giving the proper arguments. 

**STRUCTURE OF THE CODE**

We have 4 .py files containing the implementation of RoutScout

* main.py
* SendFlow.py
* LossMonitor1.py
* DelayMonitor1.py

### main.py

main.py is the starting point of execution. We have run the following command
```
python3 main.py --hops <number of hops> --pcap <pcap file name> --splitting <splitting method to consider>
```
main.py invokes sendFlows function. 

### SendFlow.py

This program parses the pcap file. Each packet from the pcap file is processed one by one. After parsing we get the TCP headers and meta data (timestamps and other necessary information) from the packet. We instantiate the Delay Monitor and Loss Monitor objects. We have 2 functions ``` populateDelayMonitor ``` and ``` populateLossMonitor ``` which are used to insert packets into the Delay and Loss Monitor. There is a function to create malicious SYN packets that are inserted into the Delay monitor. We are performing Chosen Insertion Adversary in the code. The comments in the code further explain the functions.

### LossMonitor1.py

We have a class implementation of Loss Monitor and some accessory functions. In the class declaration we have member functions to perform all operations on a Loss Monitor. By using these functions one can insert or delete a packet or verify whether a packet is expected or not. 

### DelayMonitor1.py

We have a class implementation of Delay Monitor and some accessory functions. In the class declaration we have member functions to perform all operations on a Delay Monitor. By using these functions one can insert or delete a packet or get timestamp from a pure cell. 
