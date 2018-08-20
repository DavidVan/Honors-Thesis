# Files from https://github.com/notracking/hosts-blocklists

with open('domains.txt') as domain_file:
    domain_list = list(line.strip() for line in domain_file)

domain_file = open('domains_processed.txt', 'w')

counter = 0
while (counter != len(domain_list)):
    if counter % 2 != 0:
        line = domain_list[counter]
        line = line[9:len(line)]
        line = line[:-3]
        domain_file.write(line + '\n')
    counter += 1

with open('hostnames.txt') as hostname_file:
    hostname_list = list(line.strip() for line in hostname_file)

hostname_file = open('hostnames_processed.txt', 'w')

counter = 0
while (counter != len(hostname_list)):
    if counter % 2 != 0:
        line = hostname_list[counter]
        line = line[2:len(line)]
        hostname_file.write(line + '\n')
    counter += 1