from scapy.all import *
import click

@click.command()
@click.option('-d',help='# directory')
@click.option('-n',help='# normal users', type=click.INT)
@click.option('-m',help='# attackers', type=click.INT)
def cal_traffic (d, n, m):
    f="./%s/pcap_%d_%d/all.pcap" % (d, n, m)
    # record.txt: normal bytes, attacker bytes
    out_file=open("./%s/pcap_%d_%d/record.txt" % (d, n, m), 'w')
    packets = rdpcap(f)
    first_time = -1
    attacker_set=set()
    normal_set=set()
    for i in range(4, m+4):
        attacker_set.add('10.0.0.%d' % i)
    for i in range(m+4, n+m+4):
        normal_set.add('10.0.0.%d' % i)
    normal=0
    attacker=0
    for packet in packets:
        if packet.haslayer(TCP):
            if first_time==-1:
                first_time = packet.time
            if(packet.time-first_time<=30):
                if(packet[IP].src in attacker_set or packet[IP].dst in attacker_set):
                    attacker+=len(packet)
                elif(packet[IP].src in normal_set or packet[IP].dst in normal_set):
                    normal+=len(packet)
    
    out_file.write("%d %d" % (normal, attacker))

if __name__ == '__main__':
    cal_traffic()