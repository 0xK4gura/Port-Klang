from scapy.all import *
from socket import gethostbyname
from sys import argv
from os.path import exists
from os import getcwd

# Config
def config():
	global port_range, report_close_ports, report_unestablished_ports, SYN, RST, ACK, timeout, targets
	# Generate port range
	port_range = [22, 23, 80, 443, 445, 8080]
	# for x in range(1024):
	# 	port_range.append(x+1)

	# Settings reports
	report_close_ports = False
	report_unestablished_ports = False

	# TCP Raw
	SYN, RST, ACK = 0x02, 0x04, 0x10

	# Timeout
	timeout=.2

	# Initiating
	if len(sys.argv) != 2:
		print("[X] Invalid arguments!\nUse '{} <List of Domains File>' ie. {} domains.txt".format(sys.argv[0],sys.argv[0]))
		sys.exit()
	else:
		targets = sys.argv[1]
		if exists(sys.argv[1]):
			print("\n[-] Loaded '{}'\n".format(sys.argv[1]))
		else:
			print("\n[X] Mana ada file nama '{}' weh!\nTry check balik ada tak dalam '{}'".format(sys.argv[1], os.getcwd()))
			exit()
		print("""
	█▀█ █▀█ █▀█ ▀█▀ █▄▀ █░░ ▄▀█ █▄░█ █▀▀
	█▀▀ █▄█ █▀▄ ░█░ █░█ █▄▄ █▀█ █░▀█ █▄█
		\t     -made by n0vi\n""")
		run()

# Running Program
def run():
	with open(targets, "r") as file:
		global iterator, duplicates_checker
		duplicates_checker = []
		iterator = 0
		for target in file:
			target = target.strip("\n")
			if 'https://' in target:
				target = target[8:]
			elif 'http://' in target:
				target = target[7:]
			if '/' in target[-1]:
				target = target[:-1]
			if target in duplicates_checker:
				print("\n[>>>] Skipping '{}' Reason: a duplicate".format(target))
			else:
				duplicates_checker.append(target)
				global domain_ip
				domain_ip = socket.gethostbyname(target)
				print("[>] {} - Enumerating : {} ({})".format(iterator+1, target, domain_ip))
				scan(target)
				iterator += 1

# Port Scanning
def scan(target):
	open_ports = []
	for port in port_range:
		tcp_connect =  sr1(IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=timeout, verbose=False)
		if tcp_connect and tcp_connect.haslayer(TCP):
			response_flags = tcp_connect.getlayer(TCP).flags
			if response_flags == (SYN + ACK):
				snd_rst = send(IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="AR"), verbose=False)
				print("\t[O] {} is OPEN!".format(port))
				open_ports.append(port)
			elif response_flags== (RST + ACK):
				print("\t[X] {} is CLOSED!".format(port)) if report_close_ports == True else print("",end="")
		else:
			print("\t[X] {} CLOSED due no connection established".format(port)) if report_unestablished_ports == True else print("",end="")				
	print("\n[!] Scan completed!\n\t[>>] Open ports for {} ({}) : {}\n".format(target, domain_ip, open_ports))

config()
print(">> Finished enumerating for {} websites".format(iterator))
