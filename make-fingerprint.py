# This python script takes in a tshark traffic instance saved as a csv file,
# and creates a fingerprint of that instance by filtering out unneeded information
# and creating a list of tuples of useful information. Lastly, a number of plots
# and tables are also created to visualize the fingerprint.

import csv
import argparse
import os
import pandas as pd

import matplotlib
matplotlib.use('Agg')  # Force matplotlib to not use any Xwindows backend.

import matplotlib.pyplot as plt
from pandas.plotting import table

# Add command line arguments. To see them, run "python scriptname.py --help"
parser = argparse.ArgumentParser(description='Process a packet capture.')
parser.add_argument('--filename', default='input.csv', help='Name of packet capture file.')
parser.add_argument('--ip', default='192.168.3.100', help='IP address of client.')

args = parser.parse_args()
filename = args.filename
ip = args.ip
size_list = []

# Open packet capture file and read it in and then close it
with open(filename, 'rt') as csv_file:
    file_reader = csv.reader(csv_file, delimiter=',')
    for row in file_reader:
        direction = '-' if row[2] == ip else '+'
        size = int(row[0])
        size_list.append((direction, size))

# Filter out packets with size 66
filter_list = [packet for packet in size_list if packet[1] != 66]

# Insert size markers at every direction change
size_marker_list = []
prev_direction = '+'
size_marker = 0
for size_tuple in filter_list:
    direction = size_tuple[0]
    size = size_tuple[1]
    if direction == prev_direction:
        size_marker += size
    else:  # if the direction has changed
        size_marker_list.append(('S', (size_marker / 610 + 1) * 600))
        size_marker = size
        prev_direction = direction
    size_marker_list.append(size_tuple)

# Append size marker for the last set of packets after going through the list
size_marker_list.append(('S', (size_marker / 610 + 1) * 600))

# Insert total transmitted byte markers at the end
total_byte_list = []
total_size_out = 0  # total byte count for outgoing packets
total_size_in = 0   # total byte count for incoming packets
for size_tuple in size_marker_list:
    direction = size_tuple[0]
    size = size_tuple[1]
    if direction == '+':
        total_size_out += size
    elif direction == '-':
        total_size_in += size
    total_byte_list.append(size_tuple)

# Append total number of bytes marker
total_byte_list.append(('TS+', ((total_size_out - 1) / 10000 + 1) * 10000))
total_byte_list.append(('TS-', ((total_size_in - 1) / 10000 + 1) * 10000))

# Insert HTML marker
html_marker_list = []
prev_direction = '+'
html_marker = 0
html_flag_start = 0
html_flag_end = 0
html_marker_size = 0
for size_tuple in total_byte_list:
    direction = size_tuple[0]
    size = size_tuple[1]
    if direction in ('+', '-') and html_flag_start != 3:
        html_flag_start += 1
    elif direction == '-' and html_flag_end == 0 and html_flag_start == 3:  # If the packet is part of the html document
        html_marker += size
        prev_direction = '-'
    # After the last html packet has been received
    elif direction == '+' and html_flag_end == 0 and prev_direction == '-':
        html_marker_list.append(('H', (html_marker / 610 + 1) * 600))  # Append the html marker
        html_flag_end = 1  # Reading html request has finished
    html_marker_list.append(size_tuple)
    html_marker_size = size

# Insert number markers
number_marker_list = []
prev_direction = '+'
number_count = 0
for size_tuple in html_marker_list:
    direction = size_tuple[0]
    size = size_tuple[1]
    if direction in ('+', '-'):
        if direction != prev_direction:  # Change in direction, insert number marker
            number_marker_list.append(('N', number_count))
            prev_direction = direction
            number_count = 0
        number_count += 1
    number_marker_list.append(size_tuple)

new_list = []
titles = {'-': 'Size and Direction',
          '+': 'Size and Direction',
          'N': 'Number Marker',
          'S': 'Size Marker'}
for tup in [t for t in number_marker_list if t[0] in ('S', 'N', '+', '-')]:
    marker = tup[0]
    value = -tup[1] if marker == '-' else tup[1]
    new_list.append((titles[marker], value))

filename = filename.replace(".csv", "")
filepath = filename + '/'
fileroot = filepath + filename
if not os.path.exists(filepath):
    os.mkdir(filepath)

# This list will be for markers that are appended at the end, for creating a
# table of useful marker information as part of the fingerprint
end_list_markers = [
    ('HTML', (html_marker / 610 + 1) * 600),
    ('TS+', ((total_size_out - 1) / 10000 + 1) * 10000),
    ('TS-', ((total_size_in - 1) / 10000 + 1) * 10000)
]

# Insert occurring packet size markers
occurring_list = []
unique_p = set()
unique_n = set()
for size_tuple in number_marker_list:
    direction = size_tuple[0]
    size = size_tuple[1]
    if direction == '+':
        unique_p.add(size)
    elif direction == '-':
        unique_n.add(size)
    occurring_list.append(size_tuple)
occurring_list.append(('OP+', (((len(unique_p) - 1) / 2) + 1) * 2))  # Append occurring packet marker
occurring_list.append(('OP-', (((len(unique_n) - 1) / 2) + 1) * 2))

end_list_markers.append(('OP+', (((len(unique_p) - 1) / 2) + 1) * 2))
end_list_markers.append(('OP-', (((len(unique_n) - 1) / 2) + 1) * 2))

# Insert percent incoming/outgoing packet marker and total number of packets markers
packet_list = []
n_packets_p = 0
n_packets_n = 0
for size_tuple in occurring_list:
    size = size_tuple[1]
    direction = size_tuple[0]
    if direction == '+':
        n_packets_p += 1
    elif direction == '-':
        n_packets_n += 1
    packet_list.append(size_tuple)
percent_povern_n = float(n_packets_p) / n_packets_n  # calculate incoming/outgoing percentage

# Append the incoming/outgoing percent marker
packet_list.append(('PP-', "%.2f" % (float((int((((percent_povern_n - .01) * 100) / 5) + 1) * 5)) / 100)))

# Append the total number of packet markers for both outgoing and incoming traffic
packet_list.append(('NP+', (((n_packets_p - 1) / 15) + 1) * 15))
packet_list.append(('NP-', (((n_packets_n - 1) / 15) + 1) * 15))

end_list_markers.append(('PP-', "%.2f" % (float((int((((percent_povern_n - .01) * 100) / 5) + 1) * 5)) / 100)))
end_list_markers.append(('NP+', (((n_packets_p - 1) / 15) + 1) * 15))
end_list_markers.append(('NP-', (((n_packets_n - 1) / 15) + 1) * 15))

# Create a table for the special markers that are appended at the end of the list of tuples
df = pd.DataFrame(end_list_markers, columns=['Marker', 'Packet Information'])
plt.figure()
ax = plt.subplot(721, frame_on=False)  # no visible frame
ax.xaxis.set_visible(False)  # hide the x axis
ax.yaxis.set_visible(False)  # hide the y axis
table(ax, df, loc='center')  # where df is your data frame
plt.savefig(fileroot + "-fingerprint-table.png")
plt.savefig(fileroot + "-fingerprint-table.pdf")

print(packet_list)

with open(fileroot + "-raw-packets.csv", "wb") as raw, \
        open(fileroot + "-size-and-direction.csv", "wb") as size_dir, \
        open(fileroot + "-size-markers.csv", "wb") as size, \
        open(fileroot + "-number-markers.csv", "wb") as number:

    raw_out = csv.writer(raw)
    size_dir_out = csv.writer(size_dir)
    size_out = csv.writer(size)
    number_out = csv.writer(number)
    output = {'+': size_dir_out, '-': size_dir_out, 'S': size_out, 'N': number_out}

    for pair in packet_list:
        raw_out.writerow(pair)
        value = -pair[1] if pair[0] == '-' else pair[1]
        if pair[0] in output.keys():
            output[pair[0]].writerow((value,))
