### Run the attack script:
```
python3 attack_pcap.py
``` 
This will create an attack pcap which then has to be merged with the normal pcap.

### Steps to run to merge the pcaps

Open 2 terminals in parallel: 

- In the first terminal, run:
```
sudo tcpdump -i eth0 -w name_of_the_merged_pcap.pcap
``` 
Note: Add an interface eth0 first and set the MTU to 200000. This is a one time process. Follow the instructions below: 
```
sudo ip link add eth0 type dummy
sudo ip link set dev eth0 mtu 200000
``` 

- In the second terminal, run:
```
python3 replay.py 
``` 
Note: Specify the normal pcap and attack pcap paths
