from sendFlow import sendFlows
import argparse

if __name__ == "__main__":

	#Command Arguments
    parser = argparse.ArgumentParser(description='RouteScout Argument reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    parser.add_argument('--hops', metavar='<no of hops to consider>', help='no of hops to consider', required=True)
    parser.add_argument('--splitting', metavar='<splitting method to consider>', help='1-random split 2-split based on first octet of source 3-split based on first octet of destination ', required=True)
    args = parser.parse_args()

    dataSet = args.pcap #input dataset
    hops = int(args.hops) #No of nexthops
    splitting_method=int(args.splitting) #splitting method to be used

    print(hops,dataSet)

    sendFlows(dataSet,200000000,hops,splitting_method) #calling pcap_reader function #the second parameter indicates the number of packets to process

