from scapy.all import *
import ipaddr
import mmh3
import random

#main.py code
from DelayMonitor1 import DelayMonitor
from LossMonitor1 import LossMonitor


##REQUIRED VARIABLES
TH_FIN = 0b1
TH_SYN = 0b10
TH_RST = 0b100
TH_PUSH = 0b1000
TH_ACK = 0b10000
TH_URG = 0b100000
TH_ECE = 0b1000000
TH_CWR = 0b10000000

#initializations
# delay_aggregatorA = [0,0]
# delay_aggregatorB = [0,0]

# loss_aggregatorA = [0,0]
# loss_aggregatorB = [0,0]

#Gloabal Values
flowList_delay_monitor = {} #Keep track of perFlow statistics [5tuplestring, ack seen, inverted]
flowList_loss_monitor={}  #Keep track of perFlow statistics [5tuplestring, expected, lost]

first_time_stamp=0

Delay_Aggregator=[]
Loss_Aggregator=[]
bloomfiltersize= 160000               # bloomfiltersize value is taken from the routscout paper
fpr = 0.001
hashFunctions = 9

delayMon = DelayMonitor() #instantiating Delay Monitor class and initialising it
delayMon._init_(bloomfiltersize, fpr, hashFunctions)
lossMon = LossMonitor(bloomfiltersize, fpr, hashFunctions)  #instantiating LossMonitor class and initialising it

# mon_flowsA = range(0,int(bloomfiltersize/2))
# mon_flowsB = range(int(bloomfiltersize/2),bloomfiltersize)

pack_ack = []
for i in range(bloomfiltersize):
    pack_ack.append(0)

#UTILITY FUNCTIONS

#extracts timestamp from the meta fields of the packet
def get_timestamp(meta, format="pcap"):
    if format == "pcap":
        return meta.sec + meta.usec/1000000.
    elif format == "pcapng":
        return ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol)

#converts IPV6 to IPv4 for approximations
def ipv6_to_ipv4(ipv6):

    hashed = hash(ipv6) & 0xfffffff
    ip = ipaddr.IPv4Address(hashed)
    return ip.compressed

#Takes packets from the PCAP file and populates the Delay Monitor
def populateDelayMonitor(time_stamp, src_ip, src_port, dst_ip, dst_port, protocol,syn,ack, seq, fin, hop_to_be_taken) :  #we send 5 tuple and timesatmp of the packet
                                                                        #if syn is true then its a SYN ,if syn is false then its a ACK packet
    key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol)    #we are defining key by concatenating the 5 tuple

    # print(time_stamp, syn, ack, seq)
    # print(syn)
    # print(ack)

    hash_key = hash(key)%bloomfiltersize
    # if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :
    if syn and not ack:                                           #if the packet is SYN then we are inserting the Time stamps into the Delay Monitor
        delayMon._insert_(key,time_stamp)
        flowList_delay_monitor[key] = [seq,0,0,0] #sequence number, First ACK, Invert, delay value,  
        # pack_ack[hash_key] = 1                        #we are using this dictionary pack_ack as a flag value
        # print('inserted')
    elif ack and flowList_delay_monitor.get(key) != None: #==False and pack_ack[hash_key]==1       #if the packet is ACK we clean the IBLT and get the time stamp
        
        if flowList_delay_monitor[key][1] == 0:  # check if it is the first ack for that SYN packet.
            oldSeq = flowList_delay_monitor[key][0] # Second check to make sure it is the first ack for the SYN. But we use sequence number difference = 1 
            if seq - oldSeq == 1:
                # flowList_delay_monitor[key][0] = seq
                flowList_delay_monitor[key][1] = 1 # update the flag to signal that the first ack has been seen.
                delay = delayMon._delete_(key,time_stamp)
                if delay < 0:
                    flowList_delay_monitor[key][2] = 0
                    flowList_delay_monitor[key][3] = -1     #-1 indicates that the flow cannot be decoded

                    # return
                else:
                    flowList_delay_monitor[key][2] = 1
                    flowList_delay_monitor[key][3] = delay
                    
                    #Hop Aggregation
                    Delay_Aggregator[hop_to_be_taken][0] += delay
                    Delay_Aggregator[hop_to_be_taken][1] += 1

        # if hash_key in mon_flowsA :
        #     delay_aggregatorA[0] += delay
        #     delay_aggregatorA[1] += 1

        # elif hash_key in mon_flowsB :
        #     delay_aggregatorB[0] += delay
        #     delay_aggregatorB[1] += 1

        # pack_ack[hash_key] = 0
        # print('deleted')


def populateLossMonitor(src_ip, src_port, dst_ip, dst_port, protocol,tcp_payload,packet_sequence_number,syn, ack, fin, rst,packet, hop_to_be_taken):  #we send 5 tuple , payload and sequence number of the packet
    key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol) #we are defining key by concatenating the 5 tuple
    hash_key = hash(key)%bloomfiltersize
    previous_pkt_was_fin={}

    

    # if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :

    if syn==True and ack==False and fin==False:       #if the packet is SYN packet we insert the next expected packet with sequence number = current sequence number + 1 into the Loss Monitor
        current_sequence_number=packet_sequence_number
        next_sequence_number=current_sequence_number+1   ##******************
        six_tuple_key=key+str(next_sequence_number)
        flowList_loss_monitor[key] = [0,0]
        lossMon.insert(six_tuple_key)

    elif syn==False and ack==True and tcp_payload > 0 and fin==False: #if the packet is a TCP payload packet we verify the expectation, clean the CBF and insert the next expected packet into the CBF
        current_sequence_number=packet_sequence_number
        six_tuple_key=key+str(current_sequence_number)
        
        if lossMon.verify_expectation(six_tuple_key)==True:
            lossMon.delete(six_tuple_key)   #cleaning of loss monitor
            Loss_Aggregator[hop_to_be_taken][0] += 1

            flowList_loss_monitor[key][0]+=1
            
            # if hash_key in mon_flowsA :
            #     loss_aggregatorA[0] += 1            # we are incrementing expected packets count in the aggregator

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[0] += 1
            
            # PACKET = IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,seq=packet_sequence_number, flags='A')
            # wrpcap('dump.pcap',packet, append=True)
            next_sequence_number=packet_sequence_number+tcp_payload
            next_six_tuple_key=key+str(next_sequence_number)      #inserting next packet of the flow

            lossMon.insert(next_six_tuple_key)
        
        else:
            # print("verified_expectancy_false")
            Loss_Aggregator[hop_to_be_taken][1] += 1
            if flowList_loss_monitor.get(key) is None:
                flowList_loss_monitor[key]=[0,0]
                flowList_loss_monitor[key][1]+=1

            else:
                flowList_loss_monitor[key][1]+=1
            # if hash_key in mon_flowsA :
            #     loss_aggregatorA[1] += 1            # if we cannot verify the expectancy we increment the Loss count in the aggregator

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[1] += 1
    
    elif fin==True and previous_pkt_was_fin.get(key) is None:  #if the current packet is FIN and previous packet is not FIN 
                                                
        previous_pkt_was_fin[key]=1                             #we set the dictionary to 1

        current_sequence_number=packet_sequence_number
        six_tuple_key=key+str(current_sequence_number)
        
        if lossMon.verify_expectation(six_tuple_key)==True:               # we verify whether the current FIN packet is expected we insert the next packet whose sequence number is current sequence number + 1
            lossMon.delete(six_tuple_key)   #cleaning of loss monitor
            Loss_Aggregator[hop_to_be_taken][0] += 1
            flowList_loss_monitor[key][0]+=1

            # if hash_key in mon_flowsA :                                   # if the packet is expected we increment the expected count in the aggregator
            #     loss_aggregatorA[0] += 1

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[0] += 1

            # PACKET = IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,seq=packet_sequence_number, flags='F')
            # wrpcap('dump.pcap',packet, append=True)

            next_sequence_number=packet_sequence_number+tcp_payload+1 #********************
            next_six_tuple_key=key+str(next_sequence_number)      #inserting next packet of the flow

            lossMon.insert(next_six_tuple_key)
        
        else:
            Loss_Aggregator[hop_to_be_taken][1] += 1
            if flowList_loss_monitor.get(key) is None:
                flowList_loss_monitor[key]=[0,0]
                flowList_loss_monitor[key][1]+=1

            else:
                flowList_loss_monitor[key][1]+=1
            # flowList_loss_monitor[key][1]+=1
            # print("verified_expectancy_false")
            # if hash_key in mon_flowsA :                #if the current packet is not expected we increment the Loss count in the aggregator
            #     loss_aggregatorA[1] += 1

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[1] += 1

    elif previous_pkt_was_fin.get(key) is not None :#and ack==True: if the prevvious packet is FIN 

        if fin==False:     #current packet is not FIN
            current_sequence_number=packet_sequence_number   #if the current packet is expected then expected count is incremented in the aggregator else loss count is incremented in the aggregator
            six_tuple_key=key+str(current_sequence_number)
            previous_pkt_was_fin.pop(key)

            if lossMon.verify_expectation(six_tuple_key)==True:
                lossMon.delete(six_tuple_key)   #cleaning of loss monitor
                Loss_Aggregator[hop_to_be_taken][0] += 1
                flowList_loss_monitor[key][0]+=1

                # if hash_key in mon_flowsA :
                #     loss_aggregatorA[0] += 1

                # elif hash_key in mon_flowsB :
                #     loss_aggregatorB[0] += 1

                # PACKET = IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,seq=packet_sequence_number)
                # wrpcap('dump.pcap',packet, append=True)
                
            else:
                Loss_Aggregator[hop_to_be_taken][1] += 1
                flowList_loss_monitor[key][1]+=1
                # print("verified_expectancy_false")
                # if hash_key in mon_flowsA :
                #     loss_aggregatorA[1] += 1

                # elif hash_key in mon_flowsB :
                #     loss_aggregatorB[1] += 1
            
        else:              #current packet is FIN then increment the LOSS counter in the Loss aggregator
            Loss_Aggregator[hop_to_be_taken][1] += 1
            flowList_loss_monitor[key][1]+=1
            # if hash_key in mon_flowsA :
            #     loss_aggregatorA[1] += 1

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[1] += 1

    elif rst==True:                                   #if the packet is RST  we first verify its expectation of the current rst packet and clean the CBF
        current_sequence_number=packet_sequence_number
        six_tuple_key=key+str(current_sequence_number)

        if lossMon.verify_expectation(six_tuple_key)==True:
            lossMon.delete(six_tuple_key)   #cleaning of loss monitor

            Loss_Aggregator[hop_to_be_taken][0] += 1
            flowList_loss_monitor[key][0]+=1

            # if hash_key in mon_flowsA :                   # if the packet is expected we increment the expected count in the aggregator
            #     loss_aggregatorA[0] += 1

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[0] += 1
            
            # PACKET = IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,seq=packet_sequence_number,flags='R')
            # wrpcap('dump.pcap',packet, append=True)
        
        else:                                          # if the packet is not expected we increment the loss count in the aggregator
            # print("verified_expectancy_false")
            Loss_Aggregator[hop_to_be_taken][1] += 1
            if flowList_loss_monitor.get(key) is None:
                flowList_loss_monitor[key]=[0,0]
                flowList_loss_monitor[key][1]+=1

            else:
                flowList_loss_monitor[key][1]+=1
            # flowList_loss_monitor[key][1]+=1

            # if hash_key in mon_flowsA :
            #     loss_aggregatorA[1] += 1

            # elif hash_key in mon_flowsB :
            #     loss_aggregatorB[1] += 1

def create_mal_pkt():

    ip_src = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.16"]
    # ip_src = ["10.0.0.1", "10.0.0.2"]
    ip_dst = ["20.0.0.1", "20.0.0.2", "20.0.0.3", "20.0.0.4", "20.0.0.5", "20.0.0.6", "20.0.0.7", "20.0.0.8", "20.0.0.9", "20.0.0.20", "20.0.0.11", "20.0.0.12", "20.0.0.13", "20.0.0.14", "20.0.0.15", "20.0.0.16"]
            
    ran_ip_src = random.choice(ip_src)
    ran_ip_dst = random.choice(ip_dst)

    ran_port_src = random.randint(22, 64148) #49152, 49220
    ran_port_dst = random.randint(22, 64148) #49152, 49220
    proto=6
    flow = [ran_ip_src, ran_ip_dst,ran_port_src, ran_port_dst, proto]

    return flow

def split_traffic(splitting_method,first_8_bits_value_src,first_8_bits_value_dst,hops):
    if splitting_method==1:
        x=random.randint(0,hops-1)
        return x
    elif splitting_method==2:
        offset_for_src_addr=256//hops
        y=first_8_bits_value_src//offset_for_src_addr
        return y
    elif splitting_method==3:
        offset_for_dst_addr=256//hops
        z=first_8_bits_value_dst//offset_for_dst_addr
        return z

# def check_if_tuple_is_mapping_to_non_collided_locations(src_ip,dst_ip,src_port,dst_port,proto):
#     key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(proto) 
#     if delayMon._check_for_non_collision_(key)


#pcap_reader is a function that takes a pcap file and the number of packets to be processed and replay's this packet traffic onto the Delay Monitor and Loss Monitor


## MAIN EXECUTION POINT
def sendFlows(in_file, packets_to_process,hops,splitting_method):
    """
    Args:
        in_file:
        packets_to_process:
    Returns:
    """
    
    Number_of_mal_pkts=300000
    
    time_interval=15 #15 seconds
    one_mal_pkt_time_period=15/1200
    malicious_pkt_cnt=0
    malicious_flow_set=[]
    
    for i in range(hops):
        Delay_Aggregator.append([0,0])
        Loss_Aggregator.append([0,0])

    offset_for_dst_addr=256//hops

    print(Delay_Aggregator)
    print(Loss_Aggregator)
    
    #Constants
    IP_LEN = 20
    IPv6_LEN = 40
    TCP_LEN = 14

    #variables
    packet_count = 0
    _pcap_reader = RawPcapReader(in_file)
    # for packet, meta in _pcap_reader:
    #     print('abc')
    #helper to read PCAP files (or pcapng)
    my_dict={}

    first_packet = True
    default_packet_offset = 0
    for packet, meta in _pcap_reader:     #for loop processes one packet at a time
        try:
            if first_packet:
                first_packet = False
                # check if the metadata is for pcap or pcapng
                if hasattr(meta, 'usec'):
                    pcap_format = "pcap"
                    link_type = _pcap_reader.linktype
                elif hasattr(meta, 'tshigh'):
                    pcap_format = "pcapng"
                    link_type = meta.linktype

                # check first layer
                if link_type == DLT_EN10MB:
                    default_packet_offset += 14
                elif link_type == DLT_RAW_ALT:
                    default_packet_offset += 0
                elif link_type == DLT_PPP:
                    default_packet_offset += 2

            #limit the number of packets we process
            if packet_count == packets_to_process :#packets_to_process != 0:
                break
            packet_count +=1

            #remove bytes until IP layer (this depends on the linktype)
            packet = packet[default_packet_offset:]
            #packet = packet[0:]

            #IP LAYER Parsing
            packet_offset = 0
            #print(packet[0:1],type(packet[0:1]))
            version = struct.unpack("!B", packet[0:1])
            ip_version = version[0] >> 4
            if ip_version == 4:
                # filter if the packet does not even have 20+14 bytes
                if len(packet) < (IP_LEN + TCP_LEN):
                    continue
                #get the normal ip fields. If there are options we remove it later
                ip_header = struct.unpack("!BBHHHBBHBBBBBBBB", bytes(packet[:IP_LEN]))
                # print("ip header is v4")
                # print(ip_header)
                #increase offset by layer length
                ip_header_length = (ip_header[0] & 0x0f) * 4

                packet_offset += ip_header_length

                ip_length = ip_header[2]

                protocol = ip_header[6]
                #filter protocols
                if protocol != 6:
                    continue
                #format ips
                ip_src = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[8],
                                                    ip_header[9],
                                                    ip_header[10],
                                                    ip_header[11])
                ip_dst = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[12],
                                                    ip_header[13],
                                                    ip_header[14],
                                                    ip_header[15])
                first_8_bits_value_dst=ip_header[12]
                first_8_bits_value_src=ip_header[8]
                # print(first_8_bits_value_dst)
            #parse ipv6 headers
            elif ip_version == 6:
                # filter if the packet does not even have 20+14 bytes
                if len(packet) < (IPv6_LEN + TCP_LEN):
                    #log.debug("Small packet found")
                    continue
                ip_header = struct.unpack("!LHBBQQQQ", bytes(packet[:40]))
                # print("ip header is v6")
                # print(ip_header)
                #protocol/next header
                ip_length = 40 + ip_header[1]
                ip_header_length = 40
                protocol = ip_header[2]
                if protocol != 6:
                    continue
        
                ip_src = ipv6_to_ipv4(ip_header[4] << 64 | ip_header[5])
                ip_dst = ipv6_to_ipv4(ip_header[6] << 64 | ip_header[7])
                packet_offset +=40

            else:
                continue

            #parse TCP header
            
            tcp_header = struct.unpack("!HHLLBB", bytes(packet[packet_offset:packet_offset+TCP_LEN]))
            # print("tcp header is")
            # print(tcp_header)

            #the variable names are self explanatory
            sport = tcp_header[0]
            dport = tcp_header[1]
            pkt_seq = tcp_header[2]
            tcp_header_length = ((tcp_header[4] & 0xf0) >> 4) * 4
            flags = tcp_header[5]
            # print(flags)
            syn_flag = flags & TH_SYN != 0
            fin_flag = flags & TH_FIN != 0
            ack_flag = flags & TH_ACK != 0
            rst_flag = flags & TH_RST != 0
            #update data structures
            packet_ts = get_timestamp(meta, pcap_format)

            if packet_count==1:
                first_time_stamp=packet_ts

            tcp_payload_length = ip_length - ip_header_length - tcp_header_length
            # print("tcp payload length is")
            # print(tcp_payload_length)
            packet_sequence_number=pkt_seq
            # print(pkt_seq)
            # hop_to_be_taken=first_8_bits_value_dst//offset_for_dst_addr
            # hop_to_be_taken=split_traffic(splitting_method,first_8_bits_value_src,first_8_bits_value_dst,hops)
            hop_to_be_taken=2
            # # hop_to_be_taken = random.randint(0,hops-1)

            #CHOSEN INSERTION ADVERSARY
            if malicious_pkt_cnt<Number_of_mal_pkts:
                #randomly insert
                #mal packet should map to non collision locations
                tuple=create_mal_pkt()
                src_ip_mal=tuple[0]
                dst_ip_mal=tuple[1]
                src_port_mal=tuple[2]
                dst_port_mal=tuple[3]
                proto_mal=tuple[4]
                key_mal = str(src_ip_mal) + str(dst_ip_mal) + str(src_port_mal) + str(dst_port_mal) + str(proto_mal)
                if delayMon._check_for_non_collision_(key_mal):
                    mal_pkt_ts=packet_ts+one_mal_pkt_time_period
                    mal_syn_flag=True
                    mal_ack_flag=False
                    mal_pkt_seq=0
                    mal_fin_flag=False
                    mal_hop_to_be_taken=2
                    # mal_hop_to_be_taken=random.randint(0,hops-1)
                    populateDelayMonitor(mal_pkt_ts,src_ip_mal,dst_ip_mal,src_port_mal,dst_port_mal,proto_mal,mal_syn_flag,mal_ack_flag,mal_pkt_seq,mal_fin_flag,mal_hop_to_be_taken)
                    malicious_pkt_cnt+=1
                    malicious_flow_set.append(tuple)

            #QUERY ONLY ADVERSARY
            #query only adversary attack needs to be done after some benign flows are inserted into the BF
            


            
            
            # print(packet_ts)
            #populateDelayMonitor is used to pollute delay monitor
            populateDelayMonitor(packet_ts, ip_src, sport, ip_dst, dport, protocol, syn_flag, ack_flag, pkt_seq, fin_flag,hop_to_be_taken) #hop_to_be_taken = 2
            
            # flag=0
            # key=str(ip_src)+str(ip_dst)+str(sport)+str(dport)+str(protocol)
            # if my_dict.get(key) is None:
            #     my_dict[key]=1
            #     flag=1
            # print(syn_flag , ack_flag, pkt_seq)
            
            
            #populateLossMonitor is used to pollute Loss monitor
            # populateLossMonitor(ip_src, sport, ip_dst, dport, protocol, tcp_payload_length,packet_sequence_number, syn_flag, ack_flag , fin_flag , rst_flag,packet, hop_to_be_taken)





        except Exception:
            #if this prints something just ingore it i left it for debugging, but it should happen almost never
            import traceback
            traceback.print_exc()

    # print(delay_aggregatorA)
    # print(delay_aggregatorB)

    
    # print(loss_aggregatorA)
    # print(loss_aggregatorB)

    print('###PERFLOW STATISTICS')
    # print(flowList_delay_monitor)
    # print(flowList_loss_monitor)


    agg = flowList_delay_monitor.keys()

    firstAck = 0
    Invert = 0


    for key in agg:
        firstAck = firstAck + flowList_delay_monitor[key][1]
        Invert = Invert + flowList_delay_monitor[key][2]
            

    print("Number of flows: ")
    print(len(flowList_delay_monitor))
    print("Number of first acks: ")
    print(firstAck)
    print("Number of Inverts: ")
    print(Invert)

    #sequence number, First ACK, Invert, delay value,  


    print('###AGGREGATED STATISTICS')
    print(Delay_Aggregator)
    print(Loss_Aggregator)

    print(malicious_pkt_cnt)
    print(len(malicious_flow_set))

    print(packet_count)

    



    # key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol)

    # hash_key = hash(key)%bloomfiltersize
    # if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :
    #     if flag==1:
    #         next_sequence_number=packet_sequence_number+tcp_payload
    #         six_tuple_key=key+str(next_sequence_number)
    #         lossMon.insert(six_tuple_key)
    #         # print('inserted_into_lm')
        
    #     else:
    #         # print("old flow")
    #         current_sequence_number=packet_sequence_number
    #         six_tuple_key=key+str(current_sequence_number)

    #         if lossMon.verify_expectation(six_tuple_key)==True:
    #             lossMon.delete(six_tuple_key)   #cleaning of loss monitor
    #             # print("verified_expectancy_true")
    #             if hash_key in mon_flowsA :
    #                 loss_aggregatorA[0] += 1

    #             elif hash_key in mon_flowsB :
    #                 loss_aggregatorB[0] += 1

    #             lossMon.delete(six_tuple_key)   #cleaning of loss monitor
    #             next_sequence_number=packet_sequence_number+tcp_payload
    #             next_six_tuple_key=key+str(next_sequence_number)      #inserting next packet of the flow

    #             lossMon.insert(next_six_tuple_key)
    #         else:
    #             # print("verified_expectancy_false")
    #             if hash_key in mon_flowsA :
    #                 loss_aggregatorA[1] += 1

    #             elif hash_key in mon_flowsB :
    #                 loss_aggregatorB[1] += 1



