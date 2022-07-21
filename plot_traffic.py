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
    ax_1.set_ylabel("traffic(bytes)")
    f = [".%s/all_bytes.txt" % d_cuckoo, ".%s/all_bytes.txt" % d_reset]
    markers=['.', '^']
    for i in range(0, 2):
        lines = open(f[i], 'r').readlines()
        x=np.arange(0, 35, 1) # x-axis
        time=[0]*35 # y-axis
        (base_time, bytes) = [t(s) for t,s in zip((float, int),lines[0].split())]
        for line in lines:
            (timestamp, bytes) = [t(s) for t,s in zip((float, int),line.split())]
            t=int(timestamp-base_time)
            if(t<35):
                time[t]+=bytes
        ax_1.plot(x, time, marker=markers[i])
    ax_1.legend(['our method', 'tcp-reset method'])
    fig_1.savefig("traffic_50_70.png")

if __name__ == '__main__':
    plot_traffic()