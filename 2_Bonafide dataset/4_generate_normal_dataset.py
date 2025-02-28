import pyshark
import pandas as pd
import numpy as np
import gc
import sys
import os

# Global attributes list
attributes = [
   ["frame_info", "encap_type"],    
   ["frame_info", "time"],          
   ["frame_info", "time_epoch"],    
   ["frame_info", "number"],        
   ["frame_info", "len"],           
   ["frame_info", "cap_len"],       
   ["eth", "type"],            # Ethernet Type
   ["ip", "version"],          # Internet Protocol (IP) Version
   ["ip", "hdr_len"],          # IP header length (IHL)
   ["ip", "tos"],              # IP Type of Service (TOS)
   ["ip", "id"],               # Identification
   ["ip", "flags"],            # IP flags
   ["ip", "flags.rb"],         # Reserved bit flag
   ["ip", "flags.df"],         # Don't fragment flag
   ["ip", "flags.mf"],         # More fragments flag
   ["ip", "frag_offset"],      # Fragment offset
   ["ip", "ttl"],              # Time to live
   ["ip", "proto"],            # Protocol (e.g. tcp == 6)
   ["ip", "checksum"],         # Header checksum (qualitative)
   ["ip", "src"],              # Source IP Address
   ["ip", "dst"],              # Destination IP Address
   ["ip", "len"],              # Total length
   ["ip", "dsfield"],          # Differentiated Services Field         
   ["tcp", "srcport"],         # TCP source port
   ["tcp", "dstport"],         # TCP Destination port
   ["tcp", "seq"],             # Sequence number
   ["tcp", "ack"],             # Acknowledgment number
   ["tcp", "len"],             # TCP segment length
   ["tcp", "hdr_len"],         # Header length
   ["tcp", "flags"],           # Flags
   ["tcp", "flags.fin"],       # FIN flag
   ["tcp", "flags.syn"],       # SYN flag
   ["tcp", "flags.reset"],     # RST flag
   ["tcp", "flags.push"],      # PUSH flag
   ["tcp", "flags.ack"],       # ACK flag
   ["tcp", "flags.urg"],       # URG flag
   ["tcp", "flags.cwr"],       # Congestion Window Reduced (CWR) flags
   ["tcp", "window_size"],     # Window Size
   ["tcp", "checksum"],        # Checksum
   ["tcp", "urgent_pointer"],  # Urgent pointer
   ["tcp", "options.mss_val"]  # Maximum Segment Size
]

def retrieve_attributes(packet):
   """Extract attributes from a packet and return as a list"""
   pkt_to_list = []
   
   for i in attributes:
       try:
           pkt_to_list.append(getattr(getattr(packet, i[0]), i[1]))
       except:
           pkt_to_list.append("")
           
   return pkt_to_list

def process_packets_in_batches(pcap_file, total_packets, batch_size=10000):
   """Process packets in batches and save intermediate results"""
   columns = [f"{attr[0]}.{attr[1]}" for attr in attributes]
   current_batch = []
   batch_number = 0
   processed_count = 0
   
   try:
       while processed_count < total_packets:
           # Create new capture for each batch
           cap = pyshark.FileCapture(pcap_file, display_filter="tcp")
           
           print(f"Processing batch {batch_number + 1}, starting from packet {processed_count}")
           
           # Skip already processed packets
           for _ in range(processed_count):
               next(cap)
           
           # Process current batch
           for packet in cap:
               if processed_count >= total_packets:
                   break
                   
               current_batch.append(retrieve_attributes(packet))
               processed_count += 1
               
               if len(current_batch) >= batch_size:
                   # Save batch to temporary CSV
                   batch_df = pd.DataFrame(current_batch, columns=columns)
                   batch_df.to_csv(f'./data/temp_batch_{batch_number}.csv', index=False)
                   
                   # Clear batch and memory
                   current_batch = []
                   batch_number += 1
                   del batch_df
                   gc.collect()
               
               if processed_count % 1000 == 0:
                   print(f"Processing packet {processed_count}/{total_packets}")
                   
           # Close capture after batch
           cap.close()
           del cap
           gc.collect()
           
       # Save last batch if any
       if current_batch:
           batch_df = pd.DataFrame(current_batch, columns=columns)
           batch_df.to_csv(f'./data/temp_batch_{batch_number}.csv', index=False)
           del batch_df
           gc.collect()
           
       return batch_number + 1
       
   except Exception as e:
       print(f"Error processing packets: {e}")
       raise

def combine_batch_files(num_batches, output_file):
   """Combine all batch files into final CSV and clean up temporary files"""
   print("Combining batch files...")
   
   all_dfs = []
   
   try:
       # Read and combine all batch files
       for i in range(num_batches):
           batch_file = f'./data/temp_batch_{i}.csv'
           df = pd.read_csv(batch_file)
           all_dfs.append(df)
       
       # Combine all batches
       final_df = pd.concat(all_dfs, ignore_index=True)
       
       # Save final result
       final_df.to_csv(output_file, index=False)
       print(f"Final CSV saved to {output_file}")
       
   except Exception as e:
       print(f"Error while combining files: {e}")
       raise
   
   finally:
       # Clean up temp files in finally block to ensure they're removed
       print("Cleaning up temporary files...")
       for i in range(num_batches):
           batch_file = f'./data/temp_batch_{i}.csv'
           try:
               if os.path.exists(batch_file):
                   os.remove(batch_file)
                   print(f"Removed temporary file: {batch_file}")
           except Exception as e:
               print(f"Error removing temporary file {batch_file}: {e}")
       
       # Also check for any other temp files that might have been left
       try:
           data_dir = "./data"
           for filename in os.listdir(data_dir):
               if filename.startswith("temp_batch_") and filename.endswith(".csv"):
                   file_path = os.path.join(data_dir, filename)
                   os.remove(file_path)
                   print(f"Removed additional temporary file: {filename}")
       except Exception as e:
           print(f"Error while cleaning up additional temporary files: {e}")

def count_packets(pcap_file):
   """Count total number of TCP packets in the pcap file"""
   print("Counting packets...")
   packet_count = 0
   cap = pyshark.FileCapture(pcap_file, display_filter="tcp")
   
   try:
       for _ in cap:
           packet_count += 1
           if packet_count % 1000 == 0:
               print(f"Counted {packet_count} packets...")
   except Exception as e:
       print(f"Error while counting packets: {e}")
   finally:
       cap.close()
       del cap
       gc.collect()
       
   return packet_count

def main():
   try:
       pcap_file = "./data/bonafide.pcap"
       output_file = './data/bonafide_dataset.csv'
       
       # Count total packets
       total_packets = count_packets(pcap_file)
       print(f"Total packets: {total_packets}")
       
       # Process in batches
       num_batches = process_packets_in_batches(pcap_file, total_packets)
       
       # Combine results
       combine_batch_files(num_batches, output_file)
       
       print("Processing completed successfully!")
       
   except Exception as e:
       print(f"Error in main: {e}")
       sys.exit(1)

if __name__ == "__main__":
   main()