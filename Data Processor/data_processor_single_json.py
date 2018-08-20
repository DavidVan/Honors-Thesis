import json
import socket
from joblib import Parallel, delayed
import multiprocessing
import numpy as np
import sqlite3
from sklearn import svm
from sklearn.model_selection import train_test_split

db_blacklist = []
conn = sqlite3.connect('netguard_database.db')
c = conn.cursor()
for row in c.execute('select distinct(daddr), dname from log where dname is not null'):
    db_blacklist.append(row)
db_blacklist = dict(db_blacklist)

with open("david.json") as json_file:
    test_json = json.loads(json_file.read())
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
    for i in range(len(test_json)):
        packet = test_json[i]
        if 'ip' in packet['_source']['layers'] and 'dns' not in packet['_source']['layers']:
            ips.add(packet['_source']['layers']['ip']['ip.src'])
            ips.add(packet['_source']['layers']['ip']['ip.dst'])
        elif 'ipv6' in packet['_source']['layers'] and 'dns' not in packet['_source']['layers']:
            ips.add(packet['_source']['layers']['ipv6']['ipv6.src'])
            ips.add(packet['_source']['layers']['ipv6']['ipv6.dst'])
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
    ips = all_ips()
    dictionary = {}
    list_of_ips = Parallel(n_jobs=multiprocessing.cpu_count())(delayed(resolve_host)(ip, len(ips), count + 1) for count, ip in enumerate(ips))
    for ip in list_of_ips:
        dictionary[ip[0]] = ip[1]
    return dictionary

# for i in range(len(test_json)):
#     if 'ip' in test_json[i]['_source']['layers']:
#         print(str(i) + ': ', end='')
#         print(test_json[i]['_source']['layers']['ip']['ip.src_host'])

def get_info(packet, ip_info):
    ip_version = None
    ip_src = None
    ip_src_hostname = None
    ip_dest = None
    ip_dest_hostname = None
    tcp_src = 0
    tcp_dest = 0
    udp_src = 0
    udp_dest = 0
    ssl = False
    ip_src_info = None
    ip_src_info_orig = None
    ip_src_length = 0
    ip_src_qualified_name_count = 0
    ip_dest_info = None
    ip_dest_info_orig = None
    ip_dest_length = 0
    ip_dest_qualified_name_count = 0
    # All packets should have this information
    packet_size = packet['_source']['layers']['frame']['frame.len']
    protocols = packet['_source']['layers']['frame']['frame.protocols'].split(':')
    if 'dns' in protocols:
        return None
    # Only IP packets will have this information
    if 'ip' in packet['_source']['layers']:
        ip_version = packet['_source']['layers']['ip']['ip.version']
        ip_src = packet['_source']['layers']['ip']['ip.src']
        ip_dest = packet['_source']['layers']['ip']['ip.dst']
    elif 'ipv6' in packet['_source']['layers']:
        ip_version = packet['_source']['layers']['ipv6']['ipv6.version']
        ip_src = packet['_source']['layers']['ipv6']['ipv6.src']
        ip_dest = packet['_source']['layers']['ipv6']['ipv6.dst']
    if ip_src is not None:
        ip_src_hostname = ip_info[ip_src]
    if ip_dest is not None:
        ip_dest_hostname = ip_info[ip_dest]
    if 'tcp' in packet['_source']['layers']:
        tcp_src = packet['_source']['layers']['tcp']['tcp.srcport']
        tcp_dest = packet['_source']['layers']['tcp']['tcp.dstport']
    if 'udp' in packet['_source']['layers']:
        udp_src = packet['_source']['layers']['udp']['udp.srcport']
        udp_dest = packet['_source']['layers']['udp']['udp.dstport']
    if 'ssl' in packet['_source']['layers']:
        ssl = True
    # Process String values into numerical values
    if ip_src_hostname is not None:
        ip_src_info = ip_src_hostname[0]
        ip_src_info_orig = ip_src_hostname[0]
        ip_src_qualified_name_count = len(ip_src_info.split('.'))
        ip_src_length = len(ip_src_info)
        ip_src_info = ip_src_info.rsplit('.', 2)
        try:
            if len(ip_src_info) == 2:
                ip_src_info = ip_src_info[0] + '.' + ip_src_info[1]
            else:
                ip_src_info = ip_src_info[1] + '.' + ip_src_info[2]
        except:
            ip_src_info = None
    if ip_dest_hostname is not None:
        ip_dest_info = ip_dest_hostname[0]
        ip_dest_info_orig = ip_dest_hostname[0]
        ip_dest_qualified_name_count = len(ip_dest_info.split('.'))
        ip_dest_length = len(ip_dest_info)
        ip_dest_info = ip_dest_info.rsplit('.', 2)
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
    return (
        int(packet_size), #0
        int(ip_version), #1
        ip_src_length, #2
        ip_src_qualified_name_count, #3
        ip_dest_length, #4
        ip_dest_qualified_name_count, #5
        int(tcp_src), #6
        int(tcp_dest), #7
        int(udp_src), #8
        int(udp_dest), #9
        int(ssl),
        label
    ) # 10 - Double check to see if this works...

def create_dataset():
    ip_info = process_ips()
    # Returns a numpy 2d array

    new_json = []
    for json in test_json:
        ip_src = None
        ip_dest = None
        if 'ip' in json['_source']['layers']:
            ip_src = json['_source']['layers']['ip']['ip.src']
            ip_dest = json['_source']['layers']['ip']['ip.dst']
        elif 'ipv6' in json['_source']['layers']:
            ip_src = json['_source']['layers']['ipv6']['ipv6.src']
            ip_dest = json['_source']['layers']['ipv6']['ipv6.dst']
        if ip_src is not None:
            if ip_src == '::':
                continue
            else:
                new_json.append(json)
                continue
        if ip_dest is not None:
            if ip_dest == '::':
                print('Skipping...')
                continue
            else:
                new_json.append(json)
                continue


    data_size = len(new_json)
    features = 10
    # return np.zeros((data_size, features))
    dataset = Parallel(n_jobs=multiprocessing.cpu_count())(delayed(get_info)(packet, ip_info) for count, packet in enumerate(new_json))
    ip = 0
    ipv6 = 0
    dns = 0
    other = 0
    for data in dataset:
        if data is None:
            continue
        if data[1] == 4:
            ip += 1
        elif data[1] == 6:
            ipv6 += 1
        elif data[1] == 'dns':
            dns += 1
        else:
            other += 1
    print("IPV4 " + str(ip))
    print("IPV6 " + str(ipv6))
    print("DNS " + str(dns))
    print("Other " + str(other))
    processed_data = [data for data in dataset if data is not None]
    return processed_data # Do further work to turn the data into a numpy array

def removeFromAIfInB(A,B):
    cumdims = (np.maximum(A.max(),B.max())+1)**np.arange(B.shape[1])
    return A[~np.in1d(A.dot(cumdims),B.dot(cumdims))]

if __name__ == '__main__':
    dataset = create_dataset()
    row_size = len(dataset[0])
    col_size = len(dataset)
    processed_data = np.unique(np.asarray(dataset), axis=0)
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
    recombined_train = removeFromAIfInB(recombined_train, recombined_test)

    # Split train and test again...
    X_train = recombined_train[:,:-1]
    y_train = recombined_train[:,row_size - 1]
    X_test = recombined_test[:,:-1]
    y_test = recombined_test[:,row_size - 1]
    print("Train Size: " + str(np.sum(y_train)) + "/" + str(len(y_train)))
    print("Test Size: " + str(np.sum(y_test)) + "/" + str(len(y_test)))
    clf = svm.SVC(gamma=0.001, C=100.)
    clf.fit(X_train[:-1], y_train[:-1])

    total_test_size = len(X_test)
    test_correct = 0
    for count, test in enumerate(X_test, 0):
        test = test.reshape(1, -1)
        if clf.predict(test) == y_train[count]:
            test_correct += 1

    print("Accuracy: " + str(test_correct/total_test_size))