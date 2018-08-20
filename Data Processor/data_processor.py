import os
import csv
import socket
from joblib import Parallel, delayed
import multiprocessing
import numpy as np
import sqlite3
import pickle
import itertools
import seaborn as sns
import pandas as pd
from sklearn import tree
import graphviz
import pydotplus
import PIL
import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1 import make_axes_locatable
from textwrap import wrap
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import GradientBoostingClassifier

from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin/'

db_blacklist = []
for (dirpath, dirnames, filenames) in os.walk('dataset'):
    for filename in filenames:
        if filename.endswith('db'):
            conn = sqlite3.connect('dataset' + os.sep + filename)
            c = conn.cursor()
            for row in c.execute('select distinct(daddr), dname from log where dname is not null'):
                db_blacklist.append(row)
db_blacklist = dict(db_blacklist)
print('Finished adding to db blacklist')

packets = set() # This set contains no duplicates!
packet_source_ip_count = dict()
packet_dest_ip_count = dict()
packet_source_port_count = dict()
packet_dest_port_count = dict()
packet_port_source_for_ip = dict()
packet_port_dest_for_ip = dict()
packet_source_port_for_source_ip = dict()
packet_dest_port_for_dest_ip = dict()
packet_source_occurences = dict()
packet_dest_occurences = dict()
usable_packet_count = 0
for (dirpath, dirnames, filenames) in os.walk('dataset'):
    for filename in filenames:
        if filename.endswith('csv'):
            with open('dataset' + os.sep + filename) as csv_file:
                reader = csv.reader(csv_file)
                count = 0
                for row in reader:
                    row = row[2:]
                    if count == 0:
                        count += 1
                    else:
                        if row[5] != 'DNS':
                            if row[0] in packet_source_port_for_source_ip:
                                packet_source_occurences[row[0]] += 1
                                if row[1] in packet_source_port_for_source_ip[row[0]]:
                                    packet_source_port_for_source_ip[row[0]][row[1]] += 1
                                else:
                                    # packet_source_port_for_source_ip[row[0]] = dict()
                                    packet_source_port_for_source_ip[row[0]][row[1]] = 1
                            else:
                                packet_source_occurences[row[0]] = 1
                                packet_source_port_for_source_ip[row[0]] = dict()
                                packet_source_port_for_source_ip[row[0]][row[1]] = 1
                            if row[2] in packet_dest_port_for_dest_ip:
                                packet_dest_occurences[row[2]] += 1
                                if row[3] in packet_dest_port_for_dest_ip[row[2]]:
                                    packet_dest_port_for_dest_ip[row[2]][row[3]] += 1
                                else:
                                    # packet_dest_port_for_dest_ip[row[2]] = dict()
                                    packet_dest_port_for_dest_ip[row[2]][row[3]] = 1
                            else:
                                packet_dest_occurences[row[2]] = 1
                                packet_dest_port_for_dest_ip[row[2]] = dict()
                                packet_dest_port_for_dest_ip[row[2]][row[3]] = 1
                            count += 1
# for ip, port_dict in packet_dest_port_for_dest_ip.items():
    # for port, occurences in port_dict.items():
        # print('IP: {}, Port: {}, Percentage: {}\n'.format(ip, port, occurences/packet_dest_occurences[ip]))
for (dirpath, dirnames, filenames) in os.walk('dataset'):
    for filename in filenames:
        if filename.endswith('csv'):
            with open('dataset' + os.sep + filename) as csv_file:
                reader = csv.reader(csv_file)
                count = 0
                for row in reader:
                    row = row[2:]
                    if count == 0:
                        count += 1
                    else:
                        if row[5] != 'DNS':
                            if row[0] in packet_source_ip_count:
                                packet_source_ip_count[row[0]] += 1
                            else:
                                packet_source_ip_count[row[0]] = 1

                            if row[2] in packet_dest_ip_count:
                                packet_dest_ip_count[row[2]] += 1
                            else:
                                packet_dest_ip_count[row[2]] = 1

                            if row[1] in packet_source_port_count:
                                packet_source_port_count[row[1]] += 1
                            else:
                                packet_source_port_count[row[1]] = 1

                            if row[3] in packet_dest_port_count:
                                packet_dest_port_count[row[3]] += 1
                            else:
                                packet_dest_port_count[row[3]] = 1
                            packets.add(tuple(row))
                            count += 1
                            usable_packet_count += 1
# print(packet_dest_port_count['80'])
# print(usable_packet_count)
# print(packet_dest_port_count['80'] / usable_packet_count)
# for key, value in sorted(packet_dest_ip_count.items(), reverse=True, key=lambda d_values: d_values[1]):
#     print("{} : {}".format(key, value))
# exit()

# with open("iplist.txt") as ip_blacklist_file:
#     ip_blacklist = set(line.strip() for line in ip_blacklist_file)
# with open("domainlist.txt") as domain_blacklist_file:
#     domain_blacklist = set()
#     for line in domain_blacklist_file:
#         try:
#             line_processed = line.strip().split(' ')[1]
#             domain_blacklist.add(line_processed)
#         except:
#             continue
with open('domains_processed.txt') as domain_file:
    domain_blacklist = set(line.strip() for line in domain_file)
with open('hostnames_processed.txt') as hostname_file:
    hostname_blacklist = set(line.strip() for line in hostname_file)

def all_ips():
    ips = set()
    for packet in packets: # Should contain no DNS entries!
            ips.add(packet[0]) # Source IP
            ips.add(packet[2]) # Destination IP
    return ips

# To make this parallelizable...
def resolve_host(ip, length, count):
    print('Processing {0} / {1}: {2}'.format(count, length, ip))
    try:
        host = socket.gethostbyaddr(ip)
    except:
        host = None
    return ip, host

def process_ips():
    if (not os.path.isfile('hostnames_from_ips.pickle')):
        ips = all_ips()
        dictionary = {}
        list_of_ips = Parallel(n_jobs=multiprocessing.cpu_count())(delayed(resolve_host)(ip, len(ips), count + 1) for count, ip in enumerate(ips))
        for ip in list_of_ips:
            dictionary[ip[0]] = ip[1]
        pickle_file = open('hostnames_from_ips.pickle', 'wb')
        pickle.dump(dictionary, pickle_file)
        pickle_file.close()
        return dictionary
    else:
        pickle_file = open('hostnames_from_ips.pickle', 'rb')
        return pickle.load(pickle_file)

def get_info(features_wanted, packet, ip_info):
    ip_version = None
    ip_src = None
    ip_src_hostname = None
    ip_dest = None
    ip_dest_hostname = None
    port_src = 0
    port_dest = 0
    ssl = False
    ip_src_info = None
    ip_src_info_orig = None
    ip_src_length = 0
    ip_src_subdomain_length = 0 # Subdomain length
    # ip_src_dash_count = 0 # Number of dashes in domain
    ip_dest_info = None
    ip_dest_info_orig = None
    ip_dest_length = 0
    ip_dest_subdomain_length = 0 # Subdomain length
    # ip_dest_dash_count = 0 # Number of dashes in domain
    # All packets should have this information
    packet_size = packet[7]
    protocols = packet[5]
    ip_version = packet[4]
    if ip_version == '4,4':
        ip_version = '4'
    if ip_version == '6,6':
        ip_version = '6'
    ip_src = packet[0]
    ip_dest = packet[2]

    if ip_src is not '':
        ip_src_hostname = ip_info[ip_src]
    if ip_dest is not '':
        ip_dest_hostname = ip_info[ip_dest]

    # Some packets will have this information
    if packet[1] is not '':
        port_src = packet[1]
    if packet[3] is not '':
        port_dest = packet[3]

    if packet[6] == 'Yes':
        ssl = True
    # Process String values into numerical values
    if ip_src_hostname is not None:
        # print(ip_src_hostname)
        ip_src_info = ip_src_hostname[0]
        ip_src_info_orig = ip_src_hostname[0]
        ip_src_subdomain_length = len(ip_src_info.split('.'))
        ip_src_length = len(ip_src_info)
        ip_src_info = ip_src_info.rsplit('.', 2)
        # ip_src_dash_count = ip_src_info.count('-')
        try:
            if len(ip_src_info) == 2:
                ip_src_info = ip_src_info[0] + '.' + ip_src_info[1]
            else:
                ip_src_info = ip_src_info[1] + '.' + ip_src_info[2]
        except:
            ip_src_info = None
    if ip_dest_hostname is not None:
        # print(ip_dest_hostname)
        ip_dest_info = ip_dest_hostname[0]
        ip_dest_info_orig = ip_dest_hostname[0]
        ip_dest_subdomain_length = len(ip_dest_info.split('.'))
        ip_dest_length = len(ip_dest_info)
        ip_dest_info = ip_dest_info.rsplit('.', 2)
        # ip_dest_dash_count = ip_dest_info.count('-')
        try:
            if len(ip_dest_info) == 2:
                ip_dest_info = ip_dest_info[0] + '.' + ip_dest_info[1]
            else:
                ip_dest_info = ip_dest_info[1] + '.' + ip_dest_info[2]
        except:
            ip_dest_info = None
    # return (int(packet_size), protocols, int(ip_version), ip_src, ip_src_info, ip_dest, ip_dest_info, tcp_src, tcp_dest, udp_src, udp_dest, ssl)
    # Add in keywords booleans (e.g. fbcdn, ad, etc.)
    if (ip_src != None and ip_src in db_blacklist and (db_blacklist[ip_src] in domain_blacklist or db_blacklist[ip_src] in hostname_blacklist) or ip_dest != None and ip_dest in db_blacklist and (db_blacklist[ip_dest] in domain_blacklist or db_blacklist[ip_dest] in hostname_blacklist)) or (ip_src_info != None and ip_src_info in domain_blacklist or ip_dest_info != None and ip_dest_info in domain_blacklist) or (ip_src_info_orig != None and ip_src_info_orig in hostname_blacklist or ip_dest_info_orig != None and ip_dest_info_orig in hostname_blacklist):
        label = 1
        # print("Labeled! " + str(ip_src_info or '') + " and " + str(ip_src_info_orig or '') + str(ip_dest_info or '') + " and " + str(ip_dest_info_orig or ''))
    else:
        label = 0
        # print(ip_src_info or ip_dest_info or '')
        # print("Not labeled! " + str(ip_src_info or '') + " and " + str(ip_src_info_orig or '') + str(ip_dest_info or '') + " and " + str(ip_dest_info_orig or ''))
    features_dict = {}
    features_dict['packet_size'] = int(packet_size)
    features_dict['ip_version'] = int(ip_version)
    features_dict['hostname_src_length'] = ip_src_length
    features_dict['hostname_src_depth'] = ip_src_subdomain_length
    features_dict['hostname_dest_length'] = ip_dest_length
    features_dict['hostname_dest_depth'] = ip_dest_subdomain_length
    features_dict['src_port'] = int(port_src)
    features_dict['dest_port'] = int(port_dest)
    features_dict['ssl_flag'] = int(ssl)
    features_dict['overall_src_ip_freq'] = packet_source_ip_count[ip_src] / usable_packet_count
    features_dict['overall_dest_ip_freq'] = packet_dest_ip_count[ip_dest] / usable_packet_count
    features_dict['overall_src_port_freq'] = 0 if port_src == 0 else packet_source_port_count[port_src] / usable_packet_count
    features_dict['overall_dest_port_freq'] = 0 if port_dest == 0 else packet_dest_port_count[port_dest] / usable_packet_count
    features_dict['per_ip_src_port_freq'] = 0 if port_src == 0 else packet_source_port_for_source_ip[ip_src][port_src] / packet_source_occurences[ip_src]
    features_dict['per_ip_dest_port_freq'] = 0 if port_dest == 0 else packet_dest_port_for_dest_ip[ip_dest][port_dest] / packet_dest_occurences[ip_dest]

    returned_data = [features_dict[feature] for feature in features_wanted]

    returned_data.append(label)
    return tuple(returned_data)
    # return (
    #     int(packet_size), #0
    #     # int(ip_version), #1
    #     # ip_src_length, #2
    #     # ip_src_subdomain_length, #3
    #     # ip_dest_length, #4
    #     # ip_dest_subdomain_length, #5
    #     # int(port_src), #6
    #     # int(port_dest), #7
    #     int(ssl), # 8 - Double check to see if this works...
    #     packet_source_ip_count[ip_src] / usable_packet_count, # 9
    #     packet_dest_ip_count[ip_dest] / usable_packet_count, # 10
    #     0 if port_src == 0 else packet_source_port_count[port_src] / usable_packet_count, # 11
    #     0 if port_dest == 0 else packet_dest_port_count[port_dest] / usable_packet_count, # 12
    #     # 0 if port_src == 0 else packet_source_port_for_source_ip[ip_src][port_src] / packet_source_occurences[ip_src], # 13
    #     # 0 if port_dest == 0 else packet_dest_port_for_dest_ip[ip_dest][port_dest] / packet_dest_occurences[ip_dest], # 14
    #     label
    # )

def create_dataset(features_wanted):
    ip_info = process_ips()

    new_packet_list = []
    packet_count = 1
    for packet in packets:
        # print("Processing Packet #" + str(packet_count))
        ip_src = packet[0]
        ip_dest = packet[2]
        if ip_src == '::' or ip_dest == '::':
            print('Skipping Localhost...')
            continue
        else:
            new_packet_list.append(packet)
            packet_count += 1
            continue
    data_size = len(new_packet_list)

    dataset = Parallel(n_jobs=multiprocessing.cpu_count())(delayed(get_info)(features_wanted, packet, ip_info) for count, packet in enumerate(new_packet_list))
    processed_data = [data for data in dataset if data is not None]
    return processed_data # Do further work to turn the data into a numpy array

def removeFromAIfInB(A,B):
    cumdims = (np.maximum(A.max(),B.max())+1)**np.arange(B.shape[1])
    return A[~np.in1d(A.dot(cumdims),B.dot(cumdims))]

def plot_confusion_matrix(features, cm, classes,
                          normalize=False,
                          title='Confusion matrix',
                          cmap=plt.cm.Blues):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    """
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    fmt = '.5f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label\n\nFeatures Used:\n{}'.format('\n'.join(wrap(', '.join(features), 80))))

if __name__ == '__main__':
    class_names = ['Regular Traffic', 'Ad/Tracker Traffic']
    features_to_test = dict()
    features_to_test['results1'] = [
        # 'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results2'] = [
        'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results3'] = [
        # 'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results4'] = [
        'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results5'] = [
        # 'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results6'] = [
        'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results7'] = [
        # 'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results8'] = [
        'packet_size',
        # 'ip_version',
        # 'hostname_src_length',
        # 'hostname_src_depth',
        # 'hostname_dest_length',
        # 'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results9'] = [
        # 'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results10'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results11'] = [
        # 'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results12'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results13'] = [
        # 'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results14'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results15'] = [
        # 'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results16'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]
    features_to_test['results17'] = [
        # 'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        # 'overall_src_ip_freq',
        # 'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results18'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        # 'ssl_flag',
        # 'overall_src_ip_freq',
        # 'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results19'] = [
        'packet_size',
        # 'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        # 'src_port',
        # 'dest_port',
        'ssl_flag',
        # 'overall_src_ip_freq',
        # 'overall_dest_ip_freq',
        # 'overall_src_port_freq',
        # 'overall_dest_port_freq',
        # 'per_ip_src_port_freq',
        # 'per_ip_dest_port_freq'
    ]
    features_to_test['results20'] = [
        'packet_size',
        'ip_version',
        'hostname_src_length',
        'hostname_src_depth',
        'hostname_dest_length',
        'hostname_dest_depth',
        'src_port',
        'dest_port',
        'ssl_flag',
        'overall_src_ip_freq',
        'overall_dest_ip_freq',
        'overall_src_port_freq',
        'overall_dest_port_freq',
        'per_ip_src_port_freq',
        'per_ip_dest_port_freq'
    ]

    for results_dir_name, features_wanted in features_to_test.items():
        if results_dir_name not in ['results20']:
            continue;
        dataset = create_dataset(features_wanted)
        # ssl_count = 0
        # ssl_count_true = 0
        # dataset_true = 0
        # for data in dataset:
        #     if data[len(data) - 1] == 1:
        #         dataset_true += 1
        #     if data[0] == 1:
        #         ssl_count += 1
        #         if data[len(data) - 1] == 1:
        #             ssl_count_true += 1
        # print('Percentage SSL in dataset: {}'.format(ssl_count/len(dataset)))
        # print('Percentage SSL in dataset for true examples: {}'.format(ssl_count_true/dataset_true))
        # # Remove any columns...
        # dataset = np.delete(dataset, 0, axis=1)
        row_size = len(dataset[0])
        col_size = len(dataset)
        processed_data = np.unique(np.asarray(dataset), axis=0)
        # processed_data = set([x for x in dataset])
        # processed_data = [x for x  in processed_data]
        # processed_data = np.array(processed_data)
        X = processed_data[:,:-1]
        y = processed_data[:,row_size - 1]
        print(X)
        print(y)
        # Split the data set into train and test
        X_train, X_test, y_train, y_test = train_test_split(X, y)
        # Recombine the train vectors...
        recombined_train = np.append(X_train, y_train.reshape(-1, 1), axis=1)
        # Recombine the test vectors...
        recombined_test = np.append(X_test, y_test.reshape(-1, 1), axis=1)
        # Modify Train to make sure Test is good...
        # recombined_train = removeFromAIfInB(old_recombined_train, recombined_test) # Should not be used... might be messing with floats and equality
        # recombined_train = recombined_train[recombined_train[:, 9].argsort()]

        # Split train and test again...
        # X_train = recombined_train[:,:-1]
        # y_train = recombined_train[:,row_size - 1]
        # X_test = recombined_test[:,:-1]
        # y_test = recombined_test[:,row_size - 1]

        # g = sns.pairplot(data=pd.DataFrame(recombined_train, columns=['packet_size', 'ip_version', 'ip_src_length', 'ip_src_subdomain_length', 'ip_dest_length', 'ip_dest_subdomain_length', 'port_src', 'port_dest', 'ssl', 'label']), hue='label', vars=['packet_size', 'ip_version', 'ip_src_length', 'ip_src_subdomain_length', 'ip_dest_length', 'ip_dest_subdomain_length', 'port_src', 'port_dest', 'ssl'], y_vars=['Regular Traffic', 'Ad/Tracker Traffic'])
        # plt.subplots_adjust(left=0.1, bottom=0.1)
        # plt.savefig("pairwise.png", bbox_inches="tight")

        # X_train = X_train[250000:-2500]
        # y_train = y_train[250000:-2500]
        print("Train Size: " + str(np.sum(y_train)) + " / " + str(len(y_train) - np.sum(y_train)) + " / Total: " + str(len(y_train)))
        print("Test Size: " + str(np.sum(y_test)) + " / " + str(len(y_test) - np.sum(y_test)) + " / Total: " + str(len(y_test)))
        # class_weight = {
        #     0: 10.,
        #     1: 30.
        # }
        clfs = {}
        # clfs['Logistic Regression Unbalanced'] = LogisticRegression()
        # clfs['Logistic Regression Balanced'] = LogisticRegression(class_weight = "balanced")
        # clfs['Decision Tree Unbalanced'] = tree.DecisionTreeClassifier()
        # clfs['Decision Tree Balanced'] = tree.DecisionTreeClassifier(class_weight="balanced")
        # clfs['K Nearest Neighbors - Neighbors = 1'] = KNeighborsClassifier(n_neighbors=1)
        # clfs['K Nearest Neighbors - Neighbors = 2'] = KNeighborsClassifier(n_neighbors=2)
        # clfs['K Nearest Neighbors - Neighbors = 3'] = KNeighborsClassifier(n_neighbors=3)
        # clfs['MLP Classifier - 2,5,10 Layer'] = MLPClassifier(solver='adam', alpha=1e-5, hidden_layer_sizes=(2,5,10), random_state=1)
        # clfs['Gaussian Naive Bayes'] = GaussianNB()
        clfs['Gradient Boosting Classifier - Max Depth = 10'] = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=10)
        for classifier_name, clf in clfs.items():
            clf.fit(X_train, y_train)

            total_test_size = len(X_test)
            test_correct = 0
            test_wrong = 0
            wanted_1_but_got_0 = 0
            wanted_0_but_got_1 = 0
            predictions = clf.predict(X_test)

            # results_dir_name = 'results - {}'.format(features_wanted)

            script_dir = os.path.dirname(__file__)
            results_dir = os.path.join(script_dir, results_dir_name)

            if not os.path.isdir(results_dir):
                os.makedirs(results_dir)

            classifier_dir = os.path.join(results_dir, classifier_name)

            if not os.path.isdir(classifier_dir):
                os.makedirs(classifier_dir)

            print('Classifier: {}\n'.format(classifier_name))
            print("Accuracy: " + str(accuracy_score(y_test, predictions)))
            print("Confusion Matrix:\n")
            cnf_matrix = confusion_matrix(y_test, predictions)
            print(cnf_matrix)
            np.set_printoptions(precision=5)
            print("Classification Report:\n")
            print(classification_report(y_test, predictions, digits=5))
            with open(results_dir_name + '/' + classifier_name + '/results.txt', 'w') as results_file:
                results_file.write('Features Used: {}\n'.format(features_wanted))
                results_file.write('Classifier: {}\n'.format(classifier_name))
                results_file.write('Classification Report:\n')
                results_file.write(classification_report(y_test, predictions, digits=5))
                confusion_matrix_for_write = confusion_matrix(y_test, predictions)
                norm_confusion_matrix_for_write = confusion_matrix_for_write.astype('float') / confusion_matrix_for_write.sum(axis=1)[:, np.newaxis]
                results_file.write('Confusion Matrix:\n')
                results_file.write(str(confusion_matrix_for_write) + '\n')
                results_file.write('Normalized Confusion Matrix:\n')
                results_file.write(str(norm_confusion_matrix_for_write) + '\n')
                results_file.write('Accuracy Score: {}\n'.format(accuracy_score(y_test, predictions)))

            image_list = []
            plt.figure()
            plot_confusion_matrix(features_wanted, cnf_matrix, classes=class_names, title=classifier_name + ' - Without normalization')
            plt.savefig(results_dir_name + '/' + classifier_name + '/unnormalized.png', bbox_inches='tight', pad_inches=0.3)
            image_list.append(results_dir_name + '/' + classifier_name + '/unnormalized.png')
            plt.figure()
            plot_confusion_matrix(features_wanted, cnf_matrix, classes=class_names, normalize=True, title=classifier_name + ' - Normalized')
            plt.savefig(results_dir_name + '/' + classifier_name + '/normalized.png', bbox_inches='tight', pad_inches=0.3)
            image_list.append(results_dir_name + '/' + classifier_name + '/normalized.png')
            imgs = [PIL.Image.open(img) for img in image_list]
            min_shape = sorted( [(np.sum(i.size), i.size ) for i in imgs])[0][1]
            imgs_comb = np.hstack((np.asarray(i.resize(min_shape)) for i in imgs))
            imgs_comb = PIL.Image.fromarray(imgs_comb)
            imgs_comb.save(results_dir_name + '/' + classifier_name + '/results.png')
            # plt.show()

            train_count = 0
            zero_train = 0
            for count, train in enumerate(X_train, 0):
                ans = y_train[count]
                if ans == 0:
                    train_count += 1
                    if train[1] == 0 or train[3] == 0:
                        zero_train += 1
            print(zero_train/train_count)
            exit()
            # for count, test in enumerate(X_test, 0):
            #     test = test.reshape(1, -1)
            #     ans = clf.predict(test)
            #     if ans == y_test[count]:
            #         test_correct += 1
            #     else:
            #         test_wrong += 1
            #         if ans == 0:
            #             wanted_1_but_got_0 += 1
            #         else:
            #             wanted_0_but_got_1 +=1
            #
            # print("Number Correct: " + str(test_correct))
            # print("Number Wrong: " + str(test_wrong))
            # print("How many times we wanted 0 but got 1? " + str(wanted_0_but_got_1))
            # print("How many times we wanted 1 but got 0? " + str(wanted_1_but_got_0))
            # print("Accuracy: " + str(test_correct/total_test_size))
            # features_list = ['packet_size', 'ip_version', 'ip_src_length', 'ip_src_subdomain_length', 'ip_dest_length', 'ip_dest_subdomain_length', 'port_src', 'port_dest', 'ssl', 'label']
            # features_list_no_label = ['packet_size', 'ip_version', 'ip_src_length', 'ip_src_subdomain_length', 'ip_dest_length', 'ip_dest_subdomain_length', 'port_src', 'port_dest', 'ssl', 'label']
            # If you want to generate dot files, uncomment.
            # if hasattr(clf, 'feature_importances_'):
            #     features_list_no_label = features_wanted
            #     features_list = features_list_no_label + ['label']
            #     feature_importances = zip(features_list, clf.feature_importances_)
            #     print("Feature Importances: \n")
            #     for (a, b) in feature_importances:
            #         print(a + ": " + '{:.5%}'.format(b))
            #     # dot_data = tree.export_graphviz(clf, out_file="tree.dot", feature_names=['packet_size', 'ip_version', 'ip_src_length', 'ip_src_subdomain_length', 'ip_dest_length', 'ip_dest_subdomain_length', 'port_src', 'port_dest', 'ssl'], class_names=['Regular Traffic', 'Ad/Tracker Traffic'], rounded=True, filled=True)
            #     dot_data = tree.export_graphviz(clf, out_file="tree.dot", feature_names=features_list_no_label, class_names=['Regular Traffic', 'Ad/Tracker Traffic'], rounded=True, filled=True)
            #     # dot_graph = pydotplus.graph_from_dot_data(dot_data)
            #     # dot_graph.write_png('tree.png')
            #     # graph = graphviz.Source(dot_data)
            #     # graph.render("tree")