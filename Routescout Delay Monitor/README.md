# RouteScout's Delay Monitor 

- We assume that we have next hops A and B 
- The capacity of IBLT is set to 781500 (according to the paper)
- The details on forwarding and monitoring subranges for A and B are:
![image](https://github.com/divyapathak24/test/assets/42262349/a460b0cb-8041-4129-8967-6fdb73933b1b)


### Run the Delay Monitor code:
```
python3 main.py
``` 
Note 1: Please set the input, output_csv and output_json with appropriate directory paths in the main.py.
- The csv and json files are generated for each pacp
- The demo csv and json files for a pcap is present in /demo folder

Note 2: We get the average delay statistics for next hop A and B after every 1 second interval. The CSV contains aggregated average values per interval while the JSON contains per-flow delay values during the interval
