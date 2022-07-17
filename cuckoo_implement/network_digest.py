from p4utils.mininetlib.network_API import NetworkAPI

normal_num=50
attacker_num=50

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.enableCli()
net.disableArpTables()

# Network definition
net.addP4Switch('s1')
net.setP4Source('s1','l2_learning_digest.p4')
task_file = open("tasks.txt", 'w')

# Add server
net.addHost('h1')
net.addLink('s1', 'h1')
task_file.write('h1 0 0 "python3 -m http.server 80"\n')

# Add attackers
for i in range(2, attacker_num+2):
    net.addHost('h%d' % i)
    net.addLink('s1', 'h%d' % i)
    task_file.write('h%d 0 0 "sh attack.sh"\n' % i)

# Add normal users
for i in range(attacker_num+2, normal_num+attacker_num+2):
    net.addHost('h%d' % i)
    net.addLink('s1', 'h%d' % i)
    task_file.write('h%d 0 0 "sh normal.sh"\n' % i)

# Assignment strategy
net.l2()

task_file.close()

# Give script
net.execScript("sudo python3 l2_learning_controller.py s1 digest")

# Give tasks
net.addTaskFile('tasks.txt')

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()

# Start network
net.startNetwork()