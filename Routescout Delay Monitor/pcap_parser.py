from scapy.all import *
from scapy.utils import rdpcap
import ipaddr
import mmh3 
import numpy as np
import csv
import copy

TH_FIN = 0b1
TH_SYN = 0b10
TH_RST = 0b100
TH_PUSH = 0b1000
TH_ACK = 0b10000
TH_URG = 0b100000
TH_ECE = 0b1000000
TH_CWR = 0b10000000


#main.py code
from DelayMonitor1 import IBLT
#edit
from LossMonitor1 import LossMonitor
#

capacity= 70000
delay_aggregatorA = [0.0,0,0]
delay_aggregatorB = [0.0,0,0]
unExtractable=[0,0]
Extractable=[0,0]

syn_packets = [0]
ack_packets = [0]

#edit
loss_aggregatorA = [0,0]
loss_aggregatorB = [0,0]
packA_B = [0,0]
# #

delayMon = IBLT()
delayMon._init_(70000,0.001,9) #781500

#edit
lossMon = LossMonitor(781500,0.001,9)#

#forward and monitor
#range(1,(int(math.pow(2,20))-1)+2)
forw_flowsA = range(0,int(math.pow(2,19)))
forw_flowsB = range(int(math.pow(2,19)),int(math.pow(2,20)))
mon_flowsA =   range(0,105000) #forw_flowsA
mon_flowsB =  range(int(math.pow(2,19)),int(math.pow(2,19))+105000) #forw_flowsB



pack_ack = []
for i in range((int(math.pow(2,20))-1)+2):
    pack_ack.append(0)

hashes = [0] * int(pow(2,20))


def pollute_IBLT_Loss(time_stamp, src_ip, src_port, dst_ip, dst_port, protocol,syn, fin, ack, payload,delaysA,delaysB) :

    key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol)
    
    hash_key = mmh3.hash(key)%(int(math.pow(2,20))-1)+1
    if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :
        if syn==1 and ack==0 and pack_ack[hash_key]==0:
            delayMon._insert_(key,time_stamp)
            pack_ack[hash_key] = 1
            syn_packets[0] += 1
            return hash_key
        elif fin==False and pack_ack[hash_key]==1 and payload==0:
            ack_packets[0] += 1
            delay = delayMon._delete_(key,time_stamp)
            if delay==-1:
                if hash_key in mon_flowsA :
                    delay_aggregatorA[2]+=1
                else :
                    delay_aggregatorB[2]+=1
                return
            if hash_key in mon_flowsA :
                delay_aggregatorA[0] += delay
                delay_aggregatorA[1] += 1
                Extractable[0]+=1
                packA_B[0] +=1
                delaysA.append(delay)
            elif hash_key in mon_flowsB :
                delay_aggregatorB[0] += delay
                delay_aggregatorB[1] += 1
                Extractable[1]+=1
                packA_B[1] +=1
                delaysB.append(delay)
            pack_ack[hash_key] = 0
            return hash_key

#loss monitor function edit
def fill_Loss_Monitor(src_ip, src_port, dst_ip, dst_port, protocol,tcp_payload,packet_sequence_number,flag):
    key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol)

    hash_key = mmh3.hash(key)%(int(math.pow(2,20))-1)+1
    if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :
        if flag==1:
            next_sequence_number=packet_sequence_number+tcp_payload
            six_tuple_key=key+str(next_sequence_number)
            lossMon.insert(six_tuple_key)
            # print('inserted_into_lm')
        
        else:
            # print("old flow")
            current_sequence_number=packet_sequence_number
            six_tuple_key=key+str(current_sequence_number)

            if lossMon.verify_expectation(six_tuple_key)==True:
                lossMon.delete(six_tuple_key)   #cleaning of loss monitor
                # print("verified_expectancy_true")
                if hash_key in mon_flowsA :
                    loss_aggregatorA[0] += 1

                elif hash_key in mon_flowsB :
                    loss_aggregatorB[0] += 1

                # lossMon.delete(six_tuple_key)   #cleaning of loss monitor
                next_sequence_number=packet_sequence_number+tcp_payload
                next_six_tuple_key=key+str(next_sequence_number)      #inserting next packet of the flow

                lossMon.insert(next_six_tuple_key)
            else:
                # print("verified_expectancy_false")
                if hash_key in mon_flowsA :
                    loss_aggregatorA[1] += 1

                elif hash_key in mon_flowsB :
                    loss_aggregatorB[1] += 1
    return hash_key
##


#parsing of pcap

def get_timestamp(meta, format="pcap"):
    if format == "pcap":
        return meta.sec + meta.usec/1000000.
    elif format == "pcapng":
        return ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol)

def ipv6_to_ipv4(ipv6):

    hashed = hash(ipv6) & 0xfffffff
    ip = ipaddr.IPv4Address(hashed)
    return ip.compressed
import json
def write_to_json(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file)

def pcap_reader(in_file):
    """
    Args:
        in_file:
        packets_to_process:
    Returns:
    """

    #constants
    IP_LEN = 20
    IPv6_LEN = 40
    TCP_LEN = 14

    delayA = []
    delayB = []
    Extractable_A = []
    Extractable_B = []
    UnExtractable_A = []
    UnExtractable_B = []
    packA=[]
    packB=[]

    _pcap_reader = RawPcapReader(in_file)
    #helper to read PCAP files (or pcapng)

    #edit
    my_dict={}#

    first_packet = True
    default_packet_offset = 0
    ##added
    pre_time = 0

    list_delaysA=[]
    list_delaysB=[]

    delaysA = []
    delaysB = []

    count = 0
    for packet, meta in _pcap_reader:
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
            #parse ipv6 headers
            elif ip_version == 6:
                # filter if the packet does not even have 20+14 bytes
                if len(packet) < (IPv6_LEN + TCP_LEN):
                    #log.debug("Small packet found")
                    continue
                ip_header = struct.unpack("!LHBBQQQQ", bytes(packet[:40]))
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
            sport = tcp_header[0]
            dport = tcp_header[1]
            pkt_seq = tcp_header[2]
            pkt_ack = tcp_header[3]
            tcp_header_length = ((tcp_header[4] & 0xf0) >> 4) * 4
            flags = tcp_header[5]
            syn_flag = flags & TH_SYN != 0
            fin_flag = flags & TH_FIN != 0
            ack_flag = flags & TH_ACK != 0
            #pkt_window = tcp_header[6]
            #pkt_chksum = tcp_header[7]
            #pkt_urgptr = tcp_header[8]
            tcp_dof = (tcp_header[4] & 0xf0) >> 4
            #update data structures
            packet_ts = get_timestamp(meta, pcap_format)
            # print(meta)

            tcp_payload_length = ip_length - ip_header_length - tcp_header_length

            #edit
            packet_sequence_number=pkt_seq#
            # if syn_flag:
            #     key = pollute_IBLT_Loss(packet_ts, ip_src, sport, ip_dst, dport, protocol, syn_flag, fin_flag,ack_flag,tcp_payload_length)
            # else:
            #     key,pre_delay = pollute_IBLT_Loss(packet_ts, ip_src, sport, ip_dst, dport, protocol, syn_flag, fin_flag,ack_flag,tcp_payload_length)
            #     if (key in mon_flowsA) :
            #         pre_delaysA.append(pre_delay)
            #     else:
            #         pre_delaysB.append(pre_delay)
            key = pollute_IBLT_Loss(packet_ts, ip_src, sport, ip_dst, dport, protocol, syn_flag, fin_flag,ack_flag,tcp_payload_length,delaysA,delaysB)

            #edit
            flag=0
            key=str(ip_src)+str(ip_dst)+str(sport)+str(dport)+str(protocol)
            if my_dict.get(key) is None:
                my_dict[key]=1
                flag=1
            #

            #edit
            fill_Loss_Monitor(ip_src, sport, ip_dst, dport, protocol, tcp_payload_length,packet_sequence_number, flag)
            #

            #added
            if packet_ts-pre_time >= 15:
                count += 1
                if count <= 4:
                    pre_time = packet_ts
                    #total_pack += (delay_aggregatorA[1] + delay_aggregatorB[1])
                    delA = delB = 0
                    delaysA_filtered = [value for value in delaysA if value <= 60]
                    delaysB_filtered = [value for value in delaysB if value <= 60]
                    if delay_aggregatorA[1]!=0:
                        #delA = delay_aggregatorA[0]/delay_aggregatorA[1]
                        delA = sum(delaysA_filtered) / len(delaysA_filtered)
                    if delay_aggregatorB[1]!=0:
                        #delB = delay_aggregatorB[0]/delay_aggregatorB[1]
                        delB = sum(delaysB_filtered) / len(delaysB_filtered)
                    #print(delA)
                    #print(delaysA)
                    #print(delay_aggregatorA[0])
                    delayA.append(delA)
                    delayB.append(delB)
                    Extractable_A.append(delay_aggregatorA[1])
                    Extractable_B.append(delay_aggregatorB[1])
                    UnExtractable_A.append(delay_aggregatorA[2])
                    UnExtractable_B.append(delay_aggregatorB[2])
                    
                    # if min(delA,delB)!=0 and np.abs(delA-delB)/min(delA,delB)>0.10:
                    list_delaysA.append(copy.copy(delaysA_filtered))
                    list_delaysB.append(copy.copy(delaysB_filtered))
                        #print(time)
                        
                    # print("delays A")
                    # print(delaysA)
                    # print("delays A cleared")
                    delaysA.clear()
                    delaysA_filtered.clear()
                    # print(delaysA)
                    # print("previous ")
                    # if(len(list_delaysA)>=2):
                    #     print(list_delaysA[len(list_delaysA)-2])
                    delaysB.clear()
                    delaysB_filtered.clear()
                    

                    delay_aggregatorA[0]=0.0
                    delay_aggregatorA[1]=0
                    delay_aggregatorA[2] = 0
                    delay_aggregatorB[0]=0.0
                    delay_aggregatorB[1]=0
                    delay_aggregatorB[2] = 0

                
                    loss_aggregatorA[0] = 0
                    loss_aggregatorA[1] = 0 
                
                    packA.append(packA_B[0])
                    packB.append(packA_B[1])
                    packA_B[0]=0
                    packA_B[1]=0
                    delayMon.reset()

        except Exception:
            #if this prints something just ingore it i left it for debugging, but it should happen almost never
            import traceback
            traceback.print_exc()


    # if delay_aggregatorA[1]!=0 : delayA.append(delay_aggregatorA[0]/delay_aggregatorA[1]) 
    # else: delayA.append(0.0)
    # if delay_aggregatorB[1]!=0 : delayB.append(delay_aggregatorB[0]/delay_aggregatorB[1])
    # else: delayB.append(0.0)


    # packA.append(packA_B[0])
    # packB.append(packA_B[1])
    # print ("No.of extractable flows in FlowA", Extractable[0])
    # print ("No.of extractable flows in FlowB", Extractable[1])
    # print ("Total No.of extractable flows",Extractable[0]+Extractable[1])
    

    # print ("No.of Unextractable flows in FlowA", unExtractable[0])
    # print ("No.of Unextractable flows in FlowB", unExtractable[1])
    # print ("Total No.of Unextractable flows", unExtractable[0]+unExtractable[1])

    #total_pack += (delay_aggregatorA[1] + delay_aggregatorB[1])
    delA = delB = 0
    delaysA_filtered = [value for value in delaysA if value <= 60]
    delaysB_filtered = [value for value in delaysB if value <= 60]
    if delay_aggregatorA[1]!=0:
        #delA = delay_aggregatorA[0]/delay_aggregatorA[1]
        delA = sum(delaysA_filtered) / len(delaysA_filtered)
    if delay_aggregatorB[1]!=0:
        #delB = delay_aggregatorB[0]/delay_aggregatorB[1]
        delB = sum(delaysB_filtered) / len(delaysB_filtered)
    #print(delA)
    #print(delaysA)
    #print(delay_aggregatorA[0])
    delayA.append(delA)
    delayB.append(delB)
    Extractable_A.append(delay_aggregatorA[1])
    Extractable_B.append(delay_aggregatorB[1])
    UnExtractable_A.append(delay_aggregatorA[2])
    UnExtractable_B.append(delay_aggregatorB[2])
    
    # if min(delA,delB)!=0 and np.abs(delA-delB)/min(delA,delB)>0.10:
    list_delaysA.append(copy.copy(delaysA_filtered))
    list_delaysB.append(copy.copy(delaysB_filtered))
        #print(time)
        
    # print("delays A")
    # print(delaysA)
    # print("delays A cleared")
    delaysA.clear()
    delaysA_filtered.clear()
    # print(delaysA)
    # print("previous ")
    # if(len(list_delaysA)>=2):
    #     print(list_delaysA[len(list_delaysA)-2])
    delaysB.clear()
    delaysB_filtered.clear()
    

    delay_aggregatorA[0]=0.0
    delay_aggregatorA[1]=0
    delay_aggregatorA[2] = 0
    delay_aggregatorB[0]=0.0
    delay_aggregatorB[1]=0
    delay_aggregatorB[2] = 0


    loss_aggregatorA[0] = 0
    loss_aggregatorA[1] = 0 

    packA.append(packA_B[0])
    packB.append(packA_B[1])
    packA_B[0]=0
    packA_B[1]=0
    delayMon.reset()


    delA_delB = []
    for i in range(0,len(delayA)):
        # perc_diff =0
        # if(min(delayA[i],delayB[i])!=0):
        #     perc_diff = abs(delayA[i]-delayB[i])/min(delayA[i],delayB[i])     
        Extractable = Extractable_A[i] + Extractable_B[i]
        unExtractable = UnExtractable_A[i] + UnExtractable_B[i]
        total_flows = Extractable + unExtractable
        delA_delB.append([total_flows,Extractable,unExtractable])

    # with open('data_173.csv','w') as f:
    #     csv_writer = csv.writer(f)
    #     field = ['Avg.DelayA','Avg.DelayB','Avg.DelA-Avg.DelB','count_A','count_B','Percentage difference']
    #     csv_writer.writerow(field)
    #     csv_writer.writerows(delA_delB)

    print(f'SYN-packets : {syn_packets[0]}')
    print(f'ACK-packets : {ack_packets[0]}')
    return delA_delB, list_delaysA, list_delaysB

    # import json
    # with open('delaysA_173_attack_all.json', 'w') as json_file:
    #     json.dump(list_delaysA, json_file)
    # with open('delaysB_173_attack_all.json', 'w') as json_file:
    #     json.dump(list_delaysB, json_file)
