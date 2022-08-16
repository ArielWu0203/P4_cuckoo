import matplotlib.pyplot as plt
import numpy as np

import click

@click.command()
@click.option('-d_cuckoo',help='directory of cuckoo')
@click.option('-d_reset',help='directory of tcp-reset')
def plot_traffic(d_cuckoo, d_reset):
    fig_1 = plt.figure(figsize=(10,5))
    ax_1 = fig_1.add_subplot(1, 1, 1)
    ax_1.set_xlabel("time(s)")
    ax_1.set_ylabel("traffic(KB)")
    f = [".%s/all_bytes.txt" % d_cuckoo, ".%s/all_bytes.txt" % d_reset]
    markers=['.', '^']
    total=[0, 0]
    for i in range(0, 2):
        lines = open(f[i], 'r').readlines()
        x=np.arange(0, 31, 1) # x-axis
        time=[0]*31 # y-axis
        (base_time, bytes) = [t(s) for t,s in zip((float, int),lines[0].split())]
        for line in lines:
            (timestamp, bytes) = [t(s) for t,s in zip((float, int),line.split())]
            t=int(timestamp-base_time)
            if(t<31):
                time[t]+=bytes
                total[i]+=bytes
        ax_1.plot(x, [t/1000 for t in time], marker=markers[i])
    ax_1.legend(['our method', 'tcp-reset method'])
    fig_1.savefig("traffic_50_50.png")

    total=[t/1000 for t in total]
    print(total)
    fig_2 = plt.figure(figsize=(6,5))
    ax_2= fig_2.add_subplot(1, 1, 1)
    method=["tcp-reset method", "our method"]
    x = [0, 0.5]
    ax_2.bar(x, total, width=0.1)
    ax_2.set_xticks(x, method)
    ax_2.set_xlabel("methods")
    ax_2.set_ylabel("traffic(KB)")
    fig_2.savefig("total_50_50.png")

if __name__ == '__main__':
    plot_traffic()