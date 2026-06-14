import socket
import argparse
import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BUFFER = 1024

class Crypter:
	def __init__(self, key=None):
		self.key = key if key else get_random_bytes(32) #size 32
		self.cipher = AES.new(self.key, AES.MODE_ECB)

	def encrypt(self, plaintext):
		return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

	def decrypt(self, encrypted):
		return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)

	def __str__(self):
		return "The key => {}".format(self.key.hex())


def send_encrypted_(s, cipher, message):
	s.send(cipher.encrypt(message).encode())



def enum_smtp_banner(ip):
	"""we could use command direclty !!!"""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		con = s.connect((ip, 25))
		# no decoding the banner

		res = s.recv(BUFFER).decode()
		print(" The Banner => {}".format(res))
		s.close()
	except Exception as e:
		print("Error => {}".format(e))	



def send_cmd(ip, user, command, cipher):
	# the user is from the whoever uses script !!
	lw = (command.upper()).encode()
	if lw not in (b'VRFY', b'EXPN'):
		print("Your have 2 options commands to use (VRFY/EXPN)")
		sys.exit(1)

	try:
		encoded_usr = user.encode()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, 25))
		data_sent = lw + encoded_usr + b'\r\n'
		send_encrypted_(s, cipher,data_sent)
		info_ = s.recv(BUFFER).decode()
		recv_decrypted = cipher.decrypt(info_)
		print("User verification => {}".format(recv_decrypted))

	except Exception as e:
		print("Error => {}".format(e))



def main():

	parser = argparse.ArgumentParser(description='Enumerate SMTP protocol')
	parser.add_argument("-i", "--ip", required=False,
						help=""" Enumrate target SMTP service - 
						Usage: python smtp_enum.py -i 192.168.0.1 """)
	parser.add_argument("-u", "--user", required=False,
						help=""" Assign the user from the target IP """)
	parser.add_argument("-c", "--command", required=False,
						help=""" Assign the command to be used for target IP """)
	parser.add_argument("-k", "--key", help="Encryption key", type=str, required=False)
	args = parser.parse_args()


	if args.ip and args.command and args.user and not args.key:
		parser.error("Requires key to encrypt traffic (-key)")

	if args.key:
		cipher = Crypter(bytearray.fromhex(args.key))
	else:
		cipher = Crypter()
	print(cipher)


	if args.ip and args.user and args.command:
		send_cmd(args.ip, args.user, args.command)

	elif args.ip:
		enum_smtp_banner(args.ip)

	else:
		sys.exit(1)


if __name__ == '__main__':
	main()
