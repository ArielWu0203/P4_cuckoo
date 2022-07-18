from scapy.all import *
import click

@click.command()
@click.option('-n',help='# of hosts', type=click.INT)
def cal_traffic (n):
    directs=['in', 'out']
    for i range(1, n+2):
        for dir in directs:
            f=file.open("./pcap/s1-eth%d_%s.pcap"%i, 'r')

if __name__ == '__main__':
    cal_traffic()