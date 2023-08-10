import os
import sys
import time
import math
import random
import hashlib
import argparse
import binascii
from collections import Counter

"""
Remove junk bytes from a large binary malware
by Gianni 'guelfoweb' Amato

How it works:
- Convert binary file to Hex
- Check for blocks of Hex that are 512 characters long
- They are usually hexadecimal with CC or 00 values
- Calculate the occurrences and choose the largest one
- Remove all occurrences to reduce file size

Example:
	$ ls -lh malware.exe 
	-rw-rw-r-- 1 guelfoweb guelfoweb 647M lug 13 10:33 malware.exe

	$ xxd malware.exe | tail
	286bb850: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb860: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb870: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb880: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb890: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb8a0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb8b0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb8c0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
	286bb8d0: cccc cccc cccc 986b c606 cccc cccc cccc  .......k........
	286bb8e0: cccc 608a b206 cccc cccc cccc cccc c802  ..`.............

	$ python3 reducebin.py malware.exe --entropy
	The entropy of the file is: 0.03

	$ python3 reducebin.py malware.exe 
	INPUT      : malware.exe
	Size       : 646.73 MB
	Hash MD5   : AECA52204028884A7EC8DF154F83ACAA
	String HEX : CCCCCCCC...CCCCCCCC (length = 512)
	Count      : 1321814 (occurrences)

	OUTPUT     : malware.exe.reduced
	Size       : 1.13 MB
	Hash MD5   : 753B5FBABAC18F1A2656FF18CE678C60

	Reduction  : 99.83 %
	Time       : 00:00:11
""" 

__version__ = "0.0.1"

def file_size(file):
	# returns: float (megabytes)
	file_stats = os.stat(file)
	file_megabytes = file_stats.st_size / (1024 * 1024)
	mb = round(file_megabytes, 2)
	return mb

def file_md5(file):
	#returns: string(md5)
	md5 = hashlib.md5(open(file,"rb").read()).hexdigest()
	return md5

def load_data(file):
	with open(file, "rb") as f:
		data = f.read()
	return data

def get_entropy(data):
	# returns: float (between 0 and 8)
	# a higher entropy value indicates more randomness in the data

	# store the number of times each byte appears in the data
	p = {} 
	for x in data:
		if x not in p:
			p[x] = 0
		p[x] += 1
	# total number of bytes in the data
	total = sum(p.values())
	
	entropy = 0
	# entropy of the data by iterating over the dictionary
	for x in p:
		p[x] /= total
		entropy -= p[x] * math.log2(p[x])
	return entropy

def bin_to_hex(data):
	# returns: string(hex)
	hexes = binascii.hexlify(data).decode("utf-8")
	return hexes

def occurrences_map(data, length):
	# returns: dict({hex_str: count})
	hex_counts = {}
	for i in range(0, len(data), length):
		hex_string = binascii.hexlify(data[i:i+length]).decode("utf-8")
		hex_counts[hex_string] = hex_counts.get(hex_string, 0) + 1
	return hex_counts

def most_common(hex_counts):
	# returns: int(occurrence)
	counts = Counter(hex_counts)
	most_frequent = counts.most_common(1)[0]
	return most_frequent

def reduce(binary_input, length=None, entropy=None):
	time_start = time.time()

	if not length:
		length = 512

	data  = load_data(binary_input)

	if entropy:
		print ("The entropy of the file is:", round(get_entropy(data), 2))
		sys.exit(1)

	hex_counts    = occurrences_map(data, length)
	most_frequent = most_common(hex_counts)

	string_hex  = most_frequent[0] # CCCCCCCC...CCCCCCCC
	occurrences = most_frequent[1] # 1238270
	size_input  = file_size(binary_input)
	
	if size_input < 0.20 or occurrences < 2:
		# skip if size < 20 MB or num occurrences is < 2
		print ("The file cannot be reduced.")
		sys.exit(1)

	# binary input
	print ("INPUT      :", binary_input)
	print ("Size       :", size_input, "MB")
	print ("Hash MD5   :", file_md5(binary_input).upper())
	print ("String HEX :", string_hex[:8].upper() + "..." + string_hex[-8:].upper(), "(length = {length})".format(length=str(length)))
	print ("Count      :", occurrences, "(occurrences)")

	# remove insignificant bytes
	hexes = bin_to_hex(data)
	hexes_reduced = hexes.replace(string_hex, "")
	binary_output = binary_input + ".reduced"

	# save new file
	file_reduced  = open(binary_output, "wb")
	file_reduced.write(bytearray.fromhex(hexes_reduced))

	# binary output
	size_output = file_size(binary_output)
	print ()
	print ("OUTPUT     :", binary_output)
	print ("Size       :", size_output, "MB")
	print ("Hash MD5   :", file_md5(binary_output).upper())

	# percentage
	percentage = abs(((size_output - size_input) / size_input) * 100)
	print ("\nReduction  :", round(percentage, 2), "%")

	# elapsed time
	time_end   = time.time()
	elaps_time = time_end - time_start
	print ("Time       :", time.strftime("%H:%M:%S", time.gmtime(elaps_time)))
	
# MAIN
if __name__ == "__main__":
	parser = argparse.ArgumentParser(prog="reducebin", description="Remove junk bytes from a large binary malware", epilog="Gianni 'guelfoweb' Amato")
	parser.add_argument("file", help="sample to reduce")
	parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
	parser.add_argument("-e", "--entropy", help="calculate the entropy and exit", action="store_true", required=False)
	parser.add_argument("--len", help="length hex string (default is 512)", dest="length", type=int, required=False)

	args    = parser.parse_args()
	binary  = args.file
	length  = args.length
	entropy = args.entropy

	reduce(binary, length, entropy)
