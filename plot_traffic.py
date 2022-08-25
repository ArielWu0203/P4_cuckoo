import matplotlib.pyplot as plt
import numpy as np

import click

def plot_traffic():
    fig_1 = plt.figure(figsize=(6,5))
    ax_1= fig_1.add_subplot(1, 1, 1)
    labels=['# attackers=30', '# attackers=50', '# attackers=70']
    tcp_reset=list()
    cuckoo=list()
    for i in [30, 50, 70]:
        f=open('./tcp_reset_implement/pcap_50_%d/record.txt' % i, 'r')
        line = f.readline()
        (normal, attacker) = line.split()
        normal=int(normal)
        attacker=int(attacker)
        tcp_reset.append(attacker/(attacker+normal))

    for i in [30, 50, 70]:
        f=open('./cuckoo_implement/pcap_50_%d/record.txt' % i, 'r')
        line = f.readline()
        (normal, attacker) = line.split()
        normal=int(normal)
        attacker=int(attacker)
        cuckoo.append(attacker/(attacker+normal))

    x=np.arange(len(labels))
    width=0.25
    ax_1.bar(x-width/2, tcp_reset, width, label='tcp-reset')
    ax_1.bar(x+width/2, cuckoo, width, label='our method')
    ax_1.set_xticks(x, labels)
    ax_1.set_yticks(np.arange(0, 0.7, 0.1))
    ax_1.set_xlabel("methods under different attacker numbers (# normal users=50)")
    ax_1.set_ylabel("the network traffic of malicious flows / total flows (%)")
    ax_1.legend()
    fig_1.savefig("total.png")

if __name__ == '__main__':
    plot_traffic()