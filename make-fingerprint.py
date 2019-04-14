# This python script takes in a tshark traffic instance saved as a csv file,
# and creates a fingerprint of that instance by filtering out unneeded information
# and creating a list of tuples of useful information. Lastly, a number of plots
# and tables are also created to visualize the fingerprint.

import csv
import argparse
import pandas as pd

import matplotlib

# Force matplotlib to not use any Xwindows backend.
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import seaborn as sns

import matplotlib.pylab as pyp
import matplotlib.patches as mpatches

from pandas.plotting import table


def custom_legend(colors, labels, legend_location='upper left', legend_boundary=(1, 1)):
    # Create custom legend for colors
    recs = []
    for i in range(0, len(colors)):
        recs.append(mpatches.Rectangle((0, 0), 1, 1, fc=colors[i]))
    pyp.legend(recs, labels, loc=legend_location, bbox_to_anchor=legend_boundary)


# Add command line arguments. To see them, run "python scriptname.py --help"
parser = argparse.ArgumentParser(description='Process a packet capture.')
parser.add_argument('--filename', default='facebook.csv', help='Name of packet capture file.')
parser.add_argument('--ip', default='192.168.3.100', help='IP address of client.')

print(1)

args = parser.parse_args()

filename = args.filename
ip = args.ip
sizelist = []

# Open packet capture file and read it in and then close it
with open(filename, 'rt', encoding="UTF8") as csvfile:
    filereader = csv.reader(csvfile, delimiter=',')
    for row in filereader:
        # Identify direction
        size = int(row[0])
        direction = "+"
        if row[2] == ip:
            direction = "-"
        sizelist.append((direction, size))

print(2)

# Filter out packets with size 52 - actually, 66
filterlist = []
for sizetuple in sizelist:
    size = sizetuple[1]
    if not size == 66:
        filterlist.append(sizetuple)

print(3)

# Insert size markers at every direction change
sizemarkerlist = []
previousDirection = '+'
sizeMarker = 0
for sizetuple in filterlist:
    direction = sizetuple[0]
    size = sizetuple[1]
    if direction == previousDirection:
        sizeMarker += size
    else:  # if the direction has changed
        sizemarkerlist.append(('S', (sizeMarker / 610 + 1) * 600))
        sizeMarker = size
        previousDirection = direction
    sizemarkerlist.append(sizetuple)
# Append size marker for the last set of packets after going through the list
sizemarkerlist.append(('S', (sizeMarker / 610 + 1) * 600))

print(4)

# Insert total transmitted byte markers at the end
totalByteList = []
totalSizeP = 0  # total byte count for outgoing packets
totalSizeN = 0  # total byte count for incoming packets
for sizetuple in sizemarkerlist:
    direction = sizetuple[0]
    size = sizetuple[1]
    if not direction in ['+', '-']:
        pass
    elif direction == '+':
        totalSizeP += size
    elif direction == '-':
        totalSizeN += size
    totalByteList.append(sizetuple)
totalByteList.append(('TS+', ((totalSizeP - 1) / 10000 + 1) * 10000))  # Append total number of bytes marker
totalByteList.append(('TS-', ((totalSizeN - 1) / 10000 + 1) * 10000))

print(5)

# Insert HTML marker
htmlMarkerList = []
previousDirection = '+'
htmlMarker = 0
htmlFlagStart = 0
htmlFlagEnd = 0
htmlMarkerSize = 0
for sizetuple in totalByteList:
    direction = sizetuple[0]
    size = sizetuple[1]
    if not direction in ['+', '-']:  # If the row is a marker
        pass  # do nothing
    elif direction in ['+', '-'] and htmlFlagStart != 3:
        htmlFlagStart += 1
    elif direction == '-' and htmlFlagEnd == 0 and htmlFlagStart == 3:  # If the packet is part of the html document
        htmlMarker += size
        previousDirection = '-'
    # After the last html packet has been received
    elif direction == '+' and htmlFlagEnd == 0 and previousDirection == '-':
        htmlMarkerList.append(('H', (htmlMarker / 610 + 1) * 600))  # Append the html marker
        htmlFlagEnd = 1  # Reading html request has finished
    htmlMarkerList.append(sizetuple)
    htmlMarkerSize = size

print(6)

# Insert number markers
numberMarkerList = []
onlyNumberMarkerList = []
previousDirection = '+'
numberCount = 0
for sizetuple in htmlMarkerList:
    direction = sizetuple[0]
    size = sizetuple[1]
    if not direction in ['+', '-']:
        pass
    elif direction != previousDirection:  # Change in direction, insert number marker
        numberMarkerList.append(('N', numberCount))
        onlyNumberMarkerList.append(('N', numberCount))
        previousDirection = direction
        numberCount = 0
    if direction in ['+', '-']:
        numberCount += 1
    numberMarkerList.append(sizetuple)

print(7)

newList = [tup for tup in numberMarkerList if tup[0] in ['S', 'N', '+', '-']]
newNewList = []
for newTup in newList:
    if newTup[0] == '-':
        newNewList.append(('Size and Direction', -1 * newTup[1]))
    elif newTup[0] == '+':
        newNewList.append(('Size and Direction', newTup[1]))
    elif newTup[0] == 'N':
        newNewList.append(('Number Marker', newTup[1]))
    elif newTup[0] == 'S':
        newNewList.append(('Size Marker', newTup[1]))

filename = filename.replace(".csv", "")

print(8)

df = pd.DataFrame(newNewList, columns=['Header', 'Value'])
df['Index'] = range(1, len(df) + 1)

print(9)

sns.set_style("white")
print('a')
sns.despine()
print('b')
plt.figure()
print('c')
sns_plot = sns.FacetGrid(data=df, col='Header', sharex="row", sharey=False)
print('d')
sns_plot.map(sns.barplot).set_titles('{col_name}')
print('e')
sns_plot.set(xticks=[])
print('f')
sns_plot.set(xlabel='')
print('g')
plt.savefig(filename + "-fingerprint-grid.png")

print(10)

# This list will be for markers that are appended at the end, for creating a
# table of useful marker information as part of the fingerprint
endListMarkers = []

# Append HTML marker
endListMarkers.append(('HTML', (htmlMarker / 610 + 1) * 600))

# Append total number of bytes markers
endListMarkers.append(('TS+', ((totalSizeP - 1) / 10000 + 1) * 10000))
endListMarkers.append(('TS-', ((totalSizeN - 1) / 10000 + 1) * 10000))

# Insert occurring packet size markers
occurringList = []
uniqueP = []
uniquePFlag = 0
uniqueN = []
uniqueNFlag = 0

print(11)

for sizetuple in numberMarkerList:
    direction = sizetuple[0]
    size = sizetuple[1]
    if not direction in ['+', '-']:
        pass
    elif direction == '+':
        for A in uniqueP:
            if (A == size):  # If we find a match, raise a flag and stop
                uniquePFlag = 1
                break
        if (uniquePFlag == 0):  # If there was no match in the list, append
            uniqueP.append(size)
        else:
            uniquePFlag = 0
    elif direction == '-':
        for A in uniqueN:
            if (A == size):  # If we find a match, raise a flag and stop
                uniqueNFlag = 1
                break
        if (uniqueNFlag == 0):  # If there was no match in the list, append
            uniqueN.append(size)
        else:
            uniqueNFlag = 0
    occurringList.append(sizetuple)
occurringList.append(('OP+', (((len(uniqueP) - 1) / 2) + 1) * 2))  # Append occurring packet marker
occurringList.append(('OP-', (((len(uniqueN) - 1) / 2) + 1) * 2))

endListMarkers.append(('OP+', (((len(uniqueP) - 1) / 2) + 1) * 2))
endListMarkers.append(('OP-', (((len(uniqueN) - 1) / 2) + 1) * 2))

print(12)

# Insert percent incoming/outgoing packet marker and total number of packets markers
packetList = []
nPacketsP = 0
nPacketsN = 0
for sizetuple in occurringList:
    size = sizetuple[1]
    direction = sizetuple[0]
    if not direction in ['+', '-']:
        pass
    elif direction == '+':
        nPacketsP += 1
    elif direction == '-':
        nPacketsN += 1
    packetList.append(sizetuple)
percentPoverN = float(nPacketsP) / nPacketsN  # calculate incoming/outgoing percentage
# Append the incoming/outgoing percent marker
packetList.append(('PP-', "%.2f" % (float((int(((((percentPoverN - .01) * 100)) / 5) + 1) * 5)) / 100)))
# Append the total number of packet markers for both outgoing and incoming traffic
packetList.append(('NP+', (((nPacketsP - 1) / 15) + 1) * 15))
packetList.append(('NP-', (((nPacketsN - 1) / 15) + 1) * 15))

endListMarkers.append(('PP-', "%.2f" % (float((int(((((percentPoverN - .01) * 100)) / 5) + 1) * 5)) / 100)))
endListMarkers.append(('NP+', (((nPacketsP - 1) / 15) + 1) * 15))
endListMarkers.append(('NP-', (((nPacketsN - 1) / 15) + 1) * 15))

print(13)

# Create a table for the special markers that are appended at the end of the list of tuples
df = pd.DataFrame(endListMarkers, columns=['Marker', 'Packet Information'])

plt.figure()
ax = plt.subplot(721, frame_on=False)  # no visible frame
ax.xaxis.set_visible(False)  # hide the x axis
ax.yaxis.set_visible(False)  # hide the y axis

print(14)

table(ax, df, loc='center')  # where df is your data frame

plt.savefig(filename + "-fingerprint-table.png")
plt.savefig(filename + "-fingerprint-table.pdf")

print(15)

print(packetList)
