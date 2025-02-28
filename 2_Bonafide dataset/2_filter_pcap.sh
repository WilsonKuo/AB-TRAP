#!/bin/bash

#
# This script will filter out the anomalous and suspicious packet from all splited output_*.pcap files
# and output as output_*filtered.pcap using multiple threads
#
# Filter rule is obtained from 0_extract_filter.py
#
# tshark -r input_file.pcap -w output_file.pcap -Y filter_rule
#

# Read filter rules
RULES="`cat filter_rule.txt`"

# Set maximum number of threads (adjust based on your CPU cores)
MAX_THREADS=16
RUNNING_THREADS=0

# Process all output_*.pcap files
for i in output_*.pcap; do
    # Check thread count, wait if maximum is reached
    if [ $RUNNING_THREADS -ge $MAX_THREADS ]; then
        wait -n  # Wait for any child process to complete
        RUNNING_THREADS=$((RUNNING_THREADS-1))
    fi
    
    echo "Processing: $i"
    tshark -r "${i%.*}.pcap" -w "${i%.*}filtered.pcap" -Y "$RULES" &
    
    # Increment thread counter
    RUNNING_THREADS=$((RUNNING_THREADS+1))
done

# Wait for all remaining threads to complete
wait

echo "All files processed successfully"