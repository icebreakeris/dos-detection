#!/usr/bin/python3

import socket
import time
import os
import re
from datetime import datetime

IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

class ICMPProtect():
	def __init__(self, acceptable_rate=0.1, packet_limit=100,timeout=60):
		self.timeout = timeout
		self.incoming_ip = {}
		self.banned_ips = []
		self.packet_limit = packet_limit
		self.acceptable_rate = acceptable_rate
		self.socket = None

	def start(self):
		print(f"[{datetime.now()}] Creating an ICMP socket...")
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		self.socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
		print(f"[{datetime.now()}] Listening for ICMP packets...")

		while True:
			end = time.time() + self.timeout
			#start a new loop that goes for the amount of time set in the timeout variable
			#usually 1 second
			while time.time() <= end:
				try:
					_, addr = self.socket.recvfrom(1024)
					if addr:
						addr = addr[0]
						self.__process_address(addr)
				except socket.error as ex:
					print(f"[{datetime.now()}] Exception: {ex}")

			print(f"[{datetime.now()}] Current connections: {self.incoming_ip}")
			self.incoming_ip.clear()

	def __process_address(self, addr):
		#checks if the address is in the incoming ip dictionary
		if addr in self.incoming_ip:
			#if it is, calculate its rate based on the time of last packet
			rate = time.time() - self.incoming_ip[addr]["time_of_last_packet"]

			#if the rate is lower than what we accept, then ban the ip address
			if rate <= self.acceptable_rate:
				print(f"[{datetime.now()}] {addr} exceeded acceptable rate ({self.acceptable_rate}): {rate}")
				self.ban_ip_address(addr)
				return
			
			#if the rate is okay, count how many packets the address sends
			#and if it is higher than what we allow, ban the address
			count = self.incoming_ip[addr]["count"]
			if count >= self.packet_limit:
				print(f"[{datetime.now()}] {addr} exceeded packet limit ({self.packet_limit}): {count}")
				self.ban_ip_address(addr)
				return
			
			#if all checks are okay, then update the incoming ip dictionary
			self.incoming_ip.update({addr:{"count":self.incoming_ip[addr]["count"]+1, "time_of_last_packet":time.time()}})
		else:
			#if the ip is not in the dictionary, add it using default values
			self.incoming_ip.update({addr:{"count":1, "time_of_last_packet":time.time()}})

	def ban_ip_address(self, address):
		#checks if the address is banned this session
		#this is to avoid creating identical iptables rules
		if address in self.banned_ips:
			return

		os.system(f"iptables -A INPUT -s {address} -j DROP")
		self.banned_ips.append(address)
		print(f"[{datetime.now()}] Banned {address}")

	def unban_ip_address(self, address):
		os.system(f"iptables -D INPUT -s {address} -j DROP")
		print(f"[{datetime.now()}] Unbanned {address}")

	def get_banned_addresses(self):
		addresses = []
		a = os.popen("iptables --list")
		for line in a:
			if line.startswith("DROP"):
				#finds ip address in line
				result = re.findall(IP_REGEX, line)
				if result:
					addresses.append("".join(result))
		return addresses

def main():
	if os.name != "posix":
		print("This can only run on linux operating systems!")
		return

	choices = ["Start protection", "View banned IP addresses", "Ban an IP address", "Unban an IP address", "Flush banlist", "Exit"]
	protect = ICMPProtect(acceptable_rate=0.01, packet_limit=25, timeout=1)
	cached_addresses = []
	os.system("clear")
	while True:
		print("\nICMP Flood protection toolkit\nDeveloped by Mindaugas Baltrimas (18677185)\n")
		for i, j in enumerate(choices):
			print(i, j)
		choice = int(input("choice: "))
		if choice==0:
			os.system("clear")
			print("\nStarting ICMP flood protection")
			protect.start()
		elif choice==1:
			os.system("clear")
			print("\nBanned ip addresses: ")
			cached_addresses = protect.get_banned_addresses()
			for i,j in enumerate(cached_addresses):
				print(i, j)
		elif choice==2:
			os.system("clear")
			address = input("\nEnter an address to ban (xxx.xxx.xxx.xxx): ")
			if bool(re.match(IP_REGEX, address)):
				protect.ban_ip_address(address)
		elif choice==3:
			os.system("clear")
			if not cached_addresses:
				print("Getting addresses...")
				cached_addresses = protect.get_banned_addresses()
			for i, j in enumerate(cached_addresses):
				print(i, j)
			choice = int(input("Address to unban: "))
			if choice is not None:
				protect.unban_ip_address(cached_addresses[choice])
				cached_addresses.remove(cached_addresses[choice])
		elif choice==4:
			os.system("clear")
			os.system("iptables --flush")
			print("Banlist flushed!")
		elif choice==5:
			exit()
		else:
			print("\nInvalid choice.")

if __name__ == "__main__":
	main()

