import os
import csv

packets = set() # This set contains no duplicates!
for (dirpath, dirnames, filenames) in os.walk('dataset'):
    for filename in filenames:
        if filename.endswith('csv2'):
            with open('dataset' + os.sep + filename) as csv_file:
                reader = csv.reader(csv_file)
                count = 0
                for row in reader:
                    print(tuple(row))
                    row = row[2:]
                    if count == 0:
                        count += 1
                    else:
                        if row[5] != 'DNS':
                            packets.add(tuple(row))
                            count += 1

def all_ips():
    ips = set()
    for packet in packets: # Should contain no DNS entries!
            ips.add(packet[2]) # Source IP
            ips.add(packet[4]) # Destination IP
    return ips

print(packets)