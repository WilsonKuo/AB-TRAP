import pyshark
import pandas as pd
import numpy as np
import time


all_packets = []  # Store all packets data here first
packet_count = 0
start_time = time.time()
last_checkpoint = time.time()

# List of the attributes to be retrieved from each packet
attributes = [
    ["frame_info", "encap_type"],    # 
    ["frame_info", "time"],          # 
    ["frame_info", "time_epoch"],    # 
    ["frame_info", "number"],        # 
    ["frame_info", "len"],           # 
    ["frame_info", "cap_len"],       # 
    ["eth", "type"],                 # Ethernet Type
    ["ip", "version"],               # Internet Protocol (IP) Version
    ["ip", "hdr_len"],               # IP header length (IHL)
    ["ip", "tos"],                   # IP Type of Service (TOS)
    ["ip", "id"],                    # Identification
    ["ip", "flags"],                 # IP flags
    ["ip", "flags.rb"],              # Reserved bit flag
    ["ip", "flags.df"],              # Don't fragment flag
    ["ip", "flags.mf"],              # More fragments flag
    ["ip", "frag_offset"],           # Fragment offset
    ["ip", "ttl"],                   # Time to live
    ["ip", "proto"],                 # Protocol (e.g. tcp == 6)
    ["ip", "checksum"],              # Header checksum (qualitative)
    ["ip", "src"],                   # Source IP Address
    ["ip", "dst"],                   # Destination IP Address
    ["ip", "len"],                   # Total length
    ["ip", "dsfield"],               # Differentiated Services Field       
    ["tcp", "srcport"],              # TCP source port
    ["tcp", "dstport"],              # TCP Destination port        
    ["tcp", "seq"],                  # Sequence number
    ["tcp", "ack"],                  # Acknowledgment number
    ["tcp", "len"],                  # TCP segment length
    ["tcp", "hdr_len"],              # Header length
    ["tcp", "flags"],                # Flags
    ["tcp", "flags.fin"],            # FIN flag
    ["tcp", "flags.syn"],            # SYN flag
    ["tcp", "flags.reset"],          # RST flag
    ["tcp", "flags.push"],           # PUSH flag
    ["tcp", "flags.ack"],            # ACK flag
    ["tcp", "flags.urg"],            # URG flag
    ["tcp", "flags.cwr"],            # Congestion Window Reduced (CWR) flags
    ["tcp", "window_size"],          # Window Size
    ["tcp", "checksum"],             # Checksum
    ["tcp", "urgent_pointer"],       # Urgent pointer
    ["tcp", "options.mss_val"]       # Maximum Segment Size
]

def retrieve_attributes(packet):
    global packet_count, last_checkpoint
    packet_count += 1
    if packet_count % 1000 == 0:
        current_time = time.time()
        elapsed_time = current_time - last_checkpoint
        print(f"Processing packet #{packet_count} (Last 1000 packets took {elapsed_time:.2f} seconds)")
        last_checkpoint = current_time
        
    pkt_to_list = []

    for i in attributes:
        # try-except used for packet attribute validation, if not available, fill with ""
        try:
            pkt_to_list.append(getattr(getattr(packet, i[0]), i[1]))
        except:
            pkt_to_list.append("")

    all_packets.append(pkt_to_list)  # Add to list instead of DataFrame


def main():   
    print("Starting packet processing...")
    pcap_file = "router0_output.pcap"
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp")
    cap.apply_on_packets(retrieve_attributes)
    cap.close()
    
    # Create column names
    columns = []
    for i in attributes:
        columns.append(str(i[0])+"."+str(i[1]))
    
    # Create DataFrame at once
    print("\nCreating DataFrame...")
    df = pd.DataFrame(all_packets, columns=columns)
    
    total_time = time.time() - start_time
    print(f"\nTotal packets processed: {packet_count}")
    print(f"Total processing time: {total_time:.2f} seconds")
    print(f"Average processing speed: {packet_count/total_time:.2f} packets/second")
    
    print("\nDataset preview:")
    print(df.head())
    print(f"\nDataset shape: {df.shape}")
    
    print("\nSaving dataset to CSV...")
    df.to_csv('./data/attacker_dataset.csv', index=None, header=True)
    print("Processing completed!")


if __name__ == "__main__":
    main()