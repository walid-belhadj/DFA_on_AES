
from collections import Counter
# S-Box
S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

def sbox(byte_in):
    byteout = S[byte_in]
    return byteout

# shift row inverse
def invShiftRow(in_list):
    output_list = []
    output_list.append(in_list[0])
    output_list.append(in_list[13])
    output_list.append(in_list[10])
    output_list.append(in_list[7])
    output_list.append(in_list[4])
    output_list.append(in_list[1])
    output_list.append(in_list[14])
    output_list.append(in_list[11])
    output_list.append(in_list[8])
    output_list.append(in_list[5])
    output_list.append(in_list[2])
    output_list.append(in_list[15])
    output_list.append(in_list[12])
    output_list.append(in_list[9])
    output_list.append(in_list[6])
    output_list.append(in_list[3])
    return output_list

# shift row
def norShiftRow(in_list):
    output_list = []
    output_list.append(in_list[0])
    output_list.append(in_list[5])
    output_list.append(in_list[10])
    output_list.append(in_list[15])
    output_list.append(in_list[4])
    output_list.append(in_list[9])
    output_list.append(in_list[14])
    output_list.append(in_list[3])
    output_list.append(in_list[8])
    output_list.append(in_list[13])
    output_list.append(in_list[2])
    output_list.append(in_list[7])
    output_list.append(in_list[12])
    output_list.append(in_list[1])
    output_list.append(in_list[6])
    output_list.append(in_list[11])
    return output_list
#enrg tt les texte en clair trouvé
fo = open('txt_clair.txt','w')

chiffré_tour9 = [0xf6, 0xb1, 0x08, 0xc1, 0x21, 0xec, 0xba, 0x13, 0x5a, 0xdc, 0xcc, 0x37, 0xc5, 0x1c, 0x48,  0xd1]

txtfaux1 = [0x5d, 0xaf, 0x71, 0xd4, 0xba, 0x4d, 0x95, 0x5f,0x6b, 0x13, 0x2b, 0x7d, 0x68, 0x1d, 0x7e, 0x13]

txtfaux2 = [0xf0, 0x29, 0x73, 0x46, 0xc7, 0x38, 0x1f, 0x44, 0x70, 0x0e, 0xb0, 0xec, 0xce, 0xdc, 0xd1, 0x87]

txtfaux3= [0x81, 0xe9, 0xdd, 0xf2, 0x5f, 0xd4, 0x40, 0xd6, 0x8f, 0xe8, 0x39, 0x0d, 0x56, 0x8a, 0xbf, 0x97]

ligne1_rcon= [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]

pot_msg1 = []

txt_chiff = invShiftRow(chiffré_tour9)
f1 = invShiftRow(txtfaux1)
f2 = invShiftRow(txtfaux2)
f3 = invShiftRow(txtfaux3)

for i in range(16):
    for j in range(256):
        control = 0
        for k in range(8):
            M = j
            M_p = ligne1_rcon[k]
            msg = sbox(M)
            msgp = sbox(M_p ^ M)
            msg_xor = msgp ^ msg
            cpt1 = txt_chiff[i] ^ f1[i]
            cpt2 = txt_chiff[i] ^ f2[i]
            cpt3 = txt_chiff[i] ^ f3[i]
            if msg_xor == cpt1:
                control = control + 1

            if msg_xor == cpt2:
                control = control + 1

            if msg_xor == cpt3:
                control = control + 1

            if control == 3:
                pot_msg1.append(M)
                control = 0
fo.close()

# chercher la clé du 10ème tour 
print('Le texte en clair du 10ème tour : ')
print(', '.join([hex(i) for i in pot_msg1]))

# matrice sbox des msg converti
c_msg2 = []
for i in range(16):
    c_msg2.append(sbox(pot_msg1[i]))
c_msg3 = norShiftRow(c_msg2)

# on les xor pour trouver la clé du 10ème tour 
cle_10 = []
for j in range(16):
    cle_10.append(c_msg3[j] ^ chiffré_tour9[j])
print('La clé du 10 ème tour est  : '',')
print(', '.join([hex(i) for i in cle_10]))

# trouver les clés utilisés du tour 10 a 0 
cle_tr = open('cle.txt','w')
cle_tr.write(', '.join([hex(i) for i in cle_10]))
cle_tr.write('\n')

def r_con(round_count_in):
    if round_count_in == 0:
        c = 0x0
    elif round_count_in == 1:
        c = 0x1
    elif round_count_in == 2:
        c = 0x2
    elif round_count_in == 3:
        c = 0x4
    elif round_count_in == 4:
        c = 0x8
    elif round_count_in == 5:
        c = 0x10
    elif round_count_in == 6:
        c = 0x20
    elif round_count_in == 7:
        c = 0x40
    elif round_count_in == 8:
        c = 0x80
    elif round_count_in == 9:
        c = 0x1b
    elif round_count_in == 10:
        c = 0x36
    return c

def inv_rotate(in_word):
    out_word = []
    out_word.append(in_word[1])
    out_word.append(in_word[2])
    out_word.append(in_word[3])
    out_word.append(in_word[0])
    return out_word

def list_xor(list1, list2):
    temp = []
    for i in range(4):
        j = list1[i] ^ list2[i]
        temp.append(j)
    return temp

def lists_append(t0, t1, t2, t3):
    out = []
    out.append(t0[0])
    out.append(t0[1])
    out.append(t0[2])
    out.append(t0[3])
    out.append(t1[0])
    out.append(t1[1])
    out.append(t1[2])
    out.append(t1[3])
    out.append(t2[0])
    out.append(t2[1])
    out.append(t2[2])
    out.append(t2[3])
    out.append(t3[0])
    out.append(t3[1])
    out.append(t3[2])
    out.append(t3[3])
    return out

def g_box(word_in, g_mul):
    word_out = []
    temp_word = inv_rotate(word_in)
    v0 = sbox(temp_word[0])
    v1 = sbox(temp_word[1])
    v2 = sbox(temp_word[2])
    v3 = sbox(temp_word[3])
    v0 = v0 ^ g_mul
    word_out.append(v0)
    word_out.append(v1)
    word_out.append(v2)
    word_out.append(v3)
    return word_out
key_word_0 = cle_10[0:4]
key_word_1 = cle_10[4:8]
key_word_2 = cle_10[8:12]
key_word_3 = cle_10[12:16]
temp0 = []
temp1 = []
temp2 = []
temp3 = []
out_key = []
print('Commencer la recherche de la clé inverse ')
for round_count in range(10):
    if round_count == 0:
        r = 10
    elif round_count > 0:
        r = r - 1
    if r == 10:
        w0 = key_word_0
        w1 = key_word_1
        w2 = key_word_2
        w3 = key_word_3
    else:
        w0 = temp0
        w1 = temp1
        w2 = temp2
        w3 = temp3
    g_mul = r_con(r)
    temp3 = list_xor(w2, w3)
    temp2 = list_xor(w1, w2)
    temp1 = list_xor(w0, w1)
    g_word = g_box(temp3, g_mul)
    temp0 = list_xor(w0, g_word)
    out_key = lists_append(temp0, temp1, temp2, temp3)
    cle_tr.write(', '.join([hex(i) for i in out_key]))
    cle_tr.write('\n')
print(', '.join([hex(i) for i in out_key]))
cle_tr.close()