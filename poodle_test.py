import sys
import binascii
import re
import hmac, hashlib, base64
from Crypto.Cipher import AES
from Crypto import Random
from itertools import cycle, izip

IV = Random.new().read( AES.block_size )
KEY = Random.new().read( AES.block_size )

def randkey():
	global IV
	IV = Random.new().read( AES.block_size )
	global KEY
	KEY = Random.new().read( AES.block_size )

def padding(Msg):
	return Msg + (16 - len(Msg) % 16) * chr((16 - len(Msg) - 1) % 16)

def unpad_verifier(Msg):
	msg_split = Msg[0:len(Msg) - 32 - ord(Msg[len(Msg) - 1:]) - 1]
	hash_c = Msg[len(msg_split): - ord(Msg[len(Msg)-1:]) - 1]
	#print ord(Msg[len(Msg)-1:]) 
	#ord(Msg[len(Msg)-1:]) char->ascii last char 
	sig_c = base64.b64encode(hash_c).decode()
	data = ('').join(msg_split)
	data = data.encode('string-escape')
	hash_d = hmac.new(KEY, data, hashlib.sha256).digest()
	sig_d = base64.b64encode(hash_d).decode()
	return msg_split, sig_d, sig_c

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

def encrypt(Msg):
	msg_enc = Msg.encode('string-escape')
	msg_hash = hmac.new(KEY, msg_enc, hashlib.sha256).digest()
	msg_sign = base64.b64encode(msg_hash).decode()
	msg_raw = padding( Msg + msg_hash )
	msg_key = Random.new().read( AES.block_size )
	msg_cipher = AES.new(KEY, AES.MODE_CBC, IV)
	return msg_cipher.encrypt( msg_raw )

def decrypt(Enc):
	decipher = AES.new(KEY, AES.MODE_CBC, IV)
	plaintext, sig_2, sig_c = unpad_verifier(decipher.decrypt(Enc))

	if sig_2 != sig_c:
		return 0 
	return plaintext

def run(Secret):
	secret = []
	block_len = 16

	secret_len = len(encrypt(Secret).encode('hex'))
	temp = 1
	while (True):
		length = len(encrypt("a" * temp + Secret).encode('hex'))
		if(length > secret_len):
			break
		temp += 1
	save_temp = temp
	v = []
	print "[+] Begin to poodle attack the secret"
	for block in range(secret_len / 32 - 2, 0, -1):
		for char in range(block_len):
			count = 0
			while True:
				randkey()
				request = split_len(encrypt("$"*16 + "#"*temp + Secret + "%"*(block*block_len - char)).encode('hex'),32)

				request[-1] = request[block]
				cipher = (('').join(request)).decode('hex')
				plain = decrypt(cipher)
				count += 1
				
				if plain != 0:
					temp += 1
					pbn = request[-2]
					# x = pbn
					# for i in range(x):
					# 	print "pbn: ", chr(x[i:i+1]) 
					pbi = request[block -1]
					print "pbi: ", pbi
					decipher_byte = chr(int("0f",16) ^ int(pbn[-2:],16) ^ int(pbi[-2:],16))
					secret.append(decipher_byte)
					tmp = secret[::-1]
					sys.stdout.write("\r[+] Found byte \033[36m%s\033[0m - Block %d : [%16s]" % (decipher_byte, block, ('').join(tmp)))
					print count
					sys.stdout.flush()
					break
		print "<--*************************************-->"
		secret = secret[::-1]
		v.append(('').join(secret))
		secret = []
		temp = save_temp

	v = v[::-1]
	plaintext= re.sub('^#+','',('').join(v))
	print "\n\033[32m{-} Deciphered plaintext\033[0m :", plaintext
	return v

if __name__ == '__main__':
	print "Test the poodle attack"
	Secret = "It's a test secret of poodle attack,&*()%$#@~\n\r32"
	print "[+]Secret in plaintext:", Secret
	run(Secret)
	print "[-]The end of test"
