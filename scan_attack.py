import des_scan as des
from typing import *
import itertools
#define hardware

seed = 100
dut = des.DESWithScanChain(seed)

test_code = "0BADC0DEDEADC0DE"
print("Input: " + test_code)
#do a test run of the DES with the given input and output
(check_ciphertext, _) = dut.RunEncryptOrDecrypt(test_code)
print("Ciphertext: " + check_ciphertext)
(plaintext, _) = dut.RunEncryptOrDecrypt(check_ciphertext, do_encrypt=False)
print("Plaintext: " + plaintext)


#attack step 1 - determine locations of input and L/R register
input_scan_indices = [None] * 64
left_r_scan_indices = [None] * 32
right_r_scan_indices = [None] * 32

for i in range(64):
    input = 1 << (63 - i)
    input_hexstr = '%016X' % (input)
    #print("input: " + input_hexstr)
    dut.ReInit()
    (_, scans) = dut.RunEncryptOrDecrypt(input_hexstr, True, 2)
    #get the input bit position
    #print("scans[0]: " + str(scans[0]))
    for j in range(192):
        if scans[0][j] == "1":
            input_index = j
            break
    for j in range(192):
        if scans[1][j] == "1" and j != input_index:
            lr_index = j
            break

    #input_index = scans[0].index('1')
    input_scan_indices[i] = input_index
    #in the next scan, delete the input bit as we know that one
    #scans[1] = scans[1][:input_index] + "0" + scans[1][input_index + 1:]
    #we can get the index, but we need to undo the initial permutation to get the appropriate bit
    #lr_index = scans[1].index('1')
    lr_pos = des.FINAL_PERM[i] - 1
    #print("For input %i the L/R bit is at position %i" % (i+1, lr_pos + 1))
    #print("scans[1]: " + str(scans[1]))
    if lr_pos < 32:
        left_r_scan_indices[lr_pos] = lr_index
    else:
        right_r_scan_indices[lr_pos - 32] = lr_index
    #input_scan_indices.append(math.log2(inputonly))
    #break
    
# attack step 2 - determine the round1 key

def read_scan_l_r(left_scan_indices, right_scan_indices, scan) -> Tuple[list, list]:
    l_reg = [None]*32
    r_reg = [None]*32
    for i in range(32):
        l_reg[i] = scan[left_scan_indices[i]]
        r_reg[i] = scan[right_scan_indices[i]]
    return (l_reg, r_reg)

def sboxes_output_to_possible_inputs(sboxes_output, sboxes_input) -> List[list]:
    sboxes = []
    for i in range(8):
        possible_sbox_inputs = []
        sbox_output = sboxes_output[i*4:(i+1)*4]
        sbox_input = sboxes_input[i*6:(i+1)*6]
        sbox_value = 0

        for j in range(4): #convert the binary list to a decimal value
            sbox_value |= (int(sbox_output[j]) << (3 - j))
        for row in range(4): #every sbox value appears at least once in every row
            col = des.SBOXES[i][row].index(sbox_value)
            #print("Value %i Sbox %i row %i column %i" % (sbox_value, i, row, col))
            possible_input = [
                (row & 0b10) >> 1,
                (col & 0b1000) >> 3,
                (col & 0b100) >> 2,
                (col & 0b10) >> 1,
                col & 0b1,
                row & 0b1
            ]
            for k in range(len(possible_input)):
                possible_input[k] = possible_input[k] ^ sbox_input[k]
            possible_sbox_inputs.append(possible_input)
        sboxes.append(possible_sbox_inputs)
    return sboxes

# we use three specially crafted inputs to determine the unique round1 key
# they ensure L1 is 0, and R1 has a special value in it
special_inputs = ["0000000000000000",
                  "0000AA000000AA00",
                  "8020000A8002208A"]

#permute the special_inputs to get the values the DES will use to xor against round1 key
special_inputs_permuted = []
for i in range(len(special_inputs)):
    after_ip = des.permute(des.hex2bin(special_inputs[i]), des.INITIAL_PERM, 64)
    l0 = after_ip[:32]
    r0 = after_ip[32:]
    r0_expanded = des.permute(r0, des.EXPANSION_FUNC, 48)
    r0_expanded_list = []
    for i in range(48):
        r0_expanded_list.append(int(r0_expanded[i],2))
    special_inputs_permuted.append(r0_expanded_list)

#print(special_inputs_permuted)

special_results_after_sbox = []
for special_input in special_inputs:
    (_, scans) = dut.RunEncryptOrDecrypt(special_input, True, 3)
    #print the content of the R register for scan[1]
    (l_reg, r_reg) = read_scan_l_r(left_r_scan_indices, right_r_scan_indices, scans[2])
    #print("L1: " + str(l_reg))
    #print("R1: " + str(r_reg))

    special_result = [None]*32
    for i in range(32):
        special_result[des.P_PERM[i]-1] = r_reg[i]
    special_results_after_sbox.append(special_result)

#for each of the three special results, determine possible S box inputs

#special result 0 tells us the 4 possible inputs, special result 1 and 2 are for pairing down those 4 inputs
sbox_possible_key_values = []
for i in range(len(special_results_after_sbox)):
    sbox_possible_key_values.append(sboxes_output_to_possible_inputs(special_results_after_sbox[i], special_inputs_permuted[i]))

#data stored as 
# sbox_key_values[special inputs[per sbox possibility[sbox bits]]]

#each of the sbox_key_values is a list of lists of possible inputs for that sbox for that input
# eliminate any possibility that is not present in an sbox for the other inputs
# (i.e. find the only input that is in all three sets of sbox possibilities)

possible_roundkey_bits_after_expansion = []
for sbox_index in range(8):
    possible_values = sbox_possible_key_values[0][sbox_index]
    for i in range(1,len(sbox_possible_key_values),1): #start at 1
        other_values = sbox_possible_key_values[i][sbox_index]
        #check if all possible_values are in the list of possible values for the next sbox
        #if not, remove them from the list
        #remove any elements from possible_values that is not present in other_values
        possible_values = [x for x in possible_values if x in other_values]        

    possible_roundkey_bits_after_expansion.append(possible_values)

# for i in range(len(possible_roundkey_bits_after_expansion)):
#     print("Sbox %i has %i possible roundkey values" % (i, len(possible_roundkey_bits_after_expansion[i])))
#print(possible_roundkey_bits_after_expansion)

#convert this to a set of possible round keys for the round1 key by taking the product of possible sbox inputs
# note: there should only be one possible sbox input per sbox at this point

possible_roundkeys_round1 = []
for components in itertools.product(*possible_roundkey_bits_after_expansion):
    possible_roundkey_round1 = []
    for component in components:
        possible_roundkey_round1.extend(component)
    possible_roundkeys_round1.append(possible_roundkey_round1)

roundkey_1_actual_b = dut.roundkeys_b[0]
roundkey_1_actual_val = 0
for i in range(48):
    roundkey_1_actual_val |= ((roundkey_1_actual_b[i]=="1") << (47 - i))

print("Actual key: " + dut.key_hex)
print("Round1 key: %012X" % roundkey_1_actual_val)

possible_keys = []
for possible_roundkey_round1 in possible_roundkeys_round1:
    #convert the binary list to a hex string
    possible_roundkey_round1_val = 0
    for i in range(48):
        possible_roundkey_round1_val |= (possible_roundkey_round1[i] << (47 - i))

    print("Possible round key: %012X" % possible_roundkey_round1_val)

    key1 = [None]*56
    for i in range(48):
        key1[des.KEY_PC2[i]-1] = possible_roundkey_round1[i]
    
    #right rotate each half of the key
    key1_left = key1[:28]
    key1_right = key1[28:]
    key1_left = key1_left[-1:] + key1_left[:-1]
    key1_right = key1_right[-1:] + key1_right[:-1]
    key1 = key1_left + key1_right

    key = [None]*64
    for i in range(56):
        key[des.KEY_PC1[i]-1] = key1[i]


    # key.insert(56, 'P')
    # key.insert(49, 'P')
    # key.insert(42, 'P')
    # key.insert(35, 'P')
    # key.insert(28, 'P')
    # key.insert(21, 'P')
    # key.insert(14, 'P')
    # key.insert(7, 'P')

    combined_key_possibilities = []
    for i in range(64):
        if key[i] == None:
            if (i+1) % 8 != 0:
                combined_key_possibilities.append([0,1])
            else:
                combined_key_possibilities.append([None])
        else:
            combined_key_possibilities.append([key[i]])
    
    print(combined_key_possibilities)
    
    for components in itertools.product(*combined_key_possibilities):
        possible_key_bits = []
        for component in components:
            possible_key_bits.append(component)

        for i in range(8):
            val_bits = possible_key_bits[i*8:(i+1)*8-1]
            parity_bit = 0
            for bit in val_bits:
                parity_bit ^= bit
            possible_key_bits[i*8+7] = parity_bit
        
        key_val = 0
        for i in range(64):
            key_val |= (possible_key_bits[i] << (63-i))
        
        possible_key_val = '%016X' % key_val
        possible_keys.append(possible_key_val)

print("there are %d possible keys" % len(possible_keys))
#if(dut.key_hex in possible_keys):
#    print("key is in the list of possible keys")
#else:
#    print("key is not in the list of possible keys")

for possible_key in possible_keys:
    pos_des = des.DESWithScanChain(force_key=possible_key)
    (test_ciphertext, _) = pos_des.RunEncryptOrDecrypt(test_code)
    if(test_ciphertext == check_ciphertext):
        print("key is %s" % possible_key)
        break

print("Check answer: key is " + dut.key_hex)