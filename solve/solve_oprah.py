#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import numpy
import itertools

KNOWN_PART_FIRST_BLOCK = 'hitb{'
KNOWN_PART_LAST_BLOCK = '}\x02\x02'

PLAIN_ALFABET = '0123456789abcdef'

def xor(A,B):
	return ''.join([chr(ord(a) ^ ord(b)) for a,b in zip(A, B)])

def num2hexblock(num):
	s = hex(num)[2:-1]
	while len(s) < 16:
		s = '0'+s
	return s

def xor_hexblocks(a,b):
	return num2hexblock( int(a,16) ^ int(b,16)  )

def num2vec(num, length):
	v = []
	t = num
	for i in xrange(length):
		v.append(t%2)
		t = (t>>1)
	v.reverse()
	return v


def hexstring2vec(s, length):
	return num2vec( int(s,16), length)


def find_basis(all_inputs, all_outputs, dimension, target_rank):
	print "[+] constructing basis"
	length = len(all_inputs)
	A = list(range(len(all_inputs)))
	rank = 1
	selection = []
	while rank < target_rank:	
		basis = []
		M = []
		L = []
		B = numpy.random.permutation(A)
		selection = B[0:dimension]
		for j in xrange(target_rank):
			vec = all_inputs[selection[j]]
			basis.append(vec)
			L.append( hexstring2vec(vec,dimension) ) 
		M = matrix(GF(2), target_rank, dimension, L)
		rank = M.rank()
		if rank == target_rank:
			print "[+] basis found"
			basis_output = []
			for i in xrange( len(basis) ):
				basis_output.append( all_outputs[selection[i]] )
			return basis, basis_output

def get_lin_combination(basis, target, dimension):
	M = []
	size_basis = len(basis)
	for vec in basis:
		v = hexstring2vec(vec, dimension)
		M.append(v)
	A = matrix(GF(2), size_basis, dimension, M).transpose()
	r = A.rank()
	v = hexstring2vec(target, dimension)
	M.append(v)
        A = matrix(GF(2), size_basis+1, dimension, M).transpose()
	if A.rank() > r: #in this case the target was not a lin combo of the basis, so we fail
		return False, None
	else:
		B = A.echelon_form()
		return True, B.transpose()[size_basis]

def evaluate_linear_map(input_block, basis, basis_output):
	succes, combo = get_lin_combination(basis, input_block, 64)
	if not succes:
		return False
	res = 0
	for j in xrange( len(basis) ):
		if 1 == int(combo[j]):
			res = res ^ int(basis_output[j],16)
	return res

def evaluate_inverse_linear_map(input_block, basis, basis_output):
	return evaluate_linear_map(input_block, basis_output, basis)

'''
 work on hex blocks
'''
def recover_constant(iv, ct0, pt0, basis, basis_output):
	x = xor( pt0.decode('hex'), iv.decode('hex') )
	x = x.encode('hex')
	y = evaluate_linear_map(x, basis, basis_output)
	y = num2hexblock(y)
	z = xor( ct0.decode('hex'), y.decode('hex') )
	return z.encode('hex')
	
def test_constant(c, cn, cn_1, basis, basis_output):
	x = xor( cn.decode('hex'), c.decode('hex') )
	x = x.encode('hex')
	y = evaluate_inverse_linear_map(x, basis, basis_output)
	y = num2hexblock(y)
	pn = xor( y.decode('hex'), cn_1.decode('hex') )
	s = pn
	if s[-3:] == KNOWN_PART_LAST_BLOCK:
		return True
	else:
		return False
'''
 ct_hex as array of hex blocks
 c as hex block
'''
def decrypt_ciphertext(ct_hex, c, basis, basis_output):
	num_blocks = len(ct_hex)
	pt = ''
	pt_block = 0
	for i in xrange(num_blocks-1):
		x = xor( ct_hex[i+1].decode('hex'), c.decode('hex') )
		x = x.encode('hex')
		pt_block = evaluate_inverse_linear_map(x, basis, basis_output)
		pt_block = num2hexblock(pt_block).decode('hex')
		x = xor( ct_hex[i].decode('hex'), pt_block )
		pt = pt + x.encode('hex')
	try:
		flag = pt.decode('hex') 
		print "[+] flag found: ", flag 
		return True
	except:
		return False

def recover_flag(ct, basis, basis_output):
	ct_hex = [ct[i:i+16] for i in range(0, len(ct), 16)]
	iv = ct_hex[0]
	ct0 = ct_hex[1]
        ctn_1 = ct_hex[-2]
	ctn = ct_hex[-1]
	for test in itertools.product(PLAIN_ALFABET, repeat=3):
		block = ''.join( map(str, test) )
		first_block = KNOWN_PART_FIRST_BLOCK + block
		pt0 = first_block.encode('hex') #first_block is hex block
		c = recover_constant(iv, ct0, pt0, basis, basis_output)
		if test_constant(c, ctn, ctn_1, basis, basis_output):
			if decrypt_ciphertext(ct_hex, c, basis, basis_output):
				return	
	

def get_ciphertext():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('localhost', 6001))
	buf = s.recv(1024).rstrip()
	s.close()
	return buf.split(": ")[1]

def parse_ciphertext(ct):
	ct_dec = ct.decode('hex')
	return [ct_dec[i:i+8] for i in range(0, len(ct_dec), 8)]

def get_iv_ct0_pair():
	ct = get_ciphertext()
	ct_parse = parse_ciphertext(ct)
	return ct_parse[0], ct_parse[1]

def get_pt_ct_pairs():
	lin_out = []
	lin_in = []
	iv0,ct0 = get_iv_ct0_pair()
	for i in xrange(80):
		iv1,ct1 = get_iv_ct0_pair()
		lin_in.append( xor(iv0, iv1).encode('hex') )
		lin_out.append( xor(ct0,ct1).encode('hex') )
		ct0 = ct1
		iv0 = iv1
	return lin_in, lin_out	

def solve():
	print "[+] getting pt/ct pairs for pre-computation"
	lin_in, lin_out = get_pt_ct_pairs()
	print "[+] reconctruction linear part of the affine function"
	basis, basis_output = find_basis(lin_in, lin_out, 64, 64)
	print "[+] getting additional ciphertext to recover flag"
	ct = get_ciphertext()
	recover_flag(ct, basis, basis_output)

solve()








