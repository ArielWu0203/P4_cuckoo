from scapy.all import *
import click

@click.command()
@click.option('-d',help='# directory')
def cal_traffic (d):
    f=".%s/all.pcap" % d
    out_file=open(".%s/all_bytes.txt" %d, 'w')
    packets = rdpcap(f)
    first_time = -1
    for packet in packets:
        if packet.haslayer(TCP):
            if first_time==-1:
                first_time = packet.time
            out_file.write("%f %d\n" % (packet.time-first_time, len(packet)))

if __name__ == '__main__':
    cal_traffic()