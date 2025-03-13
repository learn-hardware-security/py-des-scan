import des_scan as des
from typing import *
import itertools
#define hardware

seed = 300
dut = des.DESWithScanChain(seed)

#do a test run of the DES with a given input 
test_code = "903D3D8E2220CDDB"
print("Input: " + test_code)
(check_ciphertext, _) = dut.RunEncryptOrDecrypt(test_code, do_encrypt=True)
print("Ciphertext: " + check_ciphertext)
#(plaintext, _) = dut.RunEncryptOrDecrypt(check_ciphertext, do_encrypt=True)
#print("Plaintext: " + plaintext)

#exit(0)
#############END LISTING 1

#############LISTING 2

#Define arrays for storing the determined indices in the random scan chain
input_scan_indices = [None] * 64
left_r_scan_indices = [None] * 32
right_r_scan_indices = [None] * 32

#Input a single bit in each of the 64 possible positions and run two rounds, 
# capturing the scan chains of each cycle.
# In the first cycle, we can determine that bit of the input register
# In the second cycle, we can determine the bit of the L/R register
for i in range(64):
    dut.ReInit() #Reset the hardware 
    
    #Determine the input hex string
    input_num = 1 << (63 - i) 
    input_hexstr = '%016X' % (input_num)
    
    #Get scans for the input (we run in Encrypt mode)
    (_, scans) = dut.RunEncryptOrDecrypt(input_hexstr, True, 2)
    
    #The scans are 192 bits (represented as ASCII 0/1 characters) long. 
    # In scans[0], only one bit will be True; 
    # this represents the i-th bit in the Input register.
    for j in range(192):
        if scans[0][j] == "1":
            input_index = j
            break
    #We can store this immediately, using "i" as the position
    input_scan_indices[i] = input_index;
    
    # In scans[1], two bits will be True;
    # the one not present in the first scan represents the i-th bit in the L/R registers 
    # after Initial Permutation.
    for j in range(192):
        if scans[1][j] == "1" and j != input_index:
            lr_index = j
            break
    #We need to invert the initial permuatation before we can store this
    # For this we can use the Final Permuation table as this is the pre-computed inverse
    lr_pos = des.FINAL_PERM[i] - 1; #table values are 1-indexed
    #The low 32 lr_pos values refer to the L register, high values to R register
    if lr_pos < 32:
        left_r_scan_indices[lr_pos] = lr_index
    else:
        right_r_scan_indices[lr_pos - 32] = lr_index

#############END LISTING 2

#print("input_scan_indices: " + str(input_scan_indices))
#print("left_r_scan_indices: " + str(left_r_scan_indices))
#print("right_r_scan_indices: " + str(right_r_scan_indices))
#exit(1)

#############LISTING 3
    
# attack step 2 - determine the round1 key

#Given the set of indices for the L and R registers and the given scan chain output,
# return the contents of the L and R registers.
def read_scan_l_r(left_scan_indices, right_scan_indices, scan) -> Tuple[list, list]:
    l_reg = [None]*32
    r_reg = [None]*32
    for i in range(32):
        l_reg[i] = scan[left_scan_indices[i]]
        r_reg[i] = scan[right_scan_indices[i]]
    return (l_reg, r_reg)

#############END LISTING 3

#############LISTING 4

#Given the concatenated output of the s-boxes (i.e. point 'c' in Fig. 2),
# (as a list of bits)
# and the concatenated input to the xor function (i.e. point 'a' in Fig. 2),
# (also as a list of bits)
# return the list of possible values for each s-box (i.e. list of lists).
def sboxes_output_to_possible_inputs(sboxes_output, sboxes_xor_input) -> List[list]:
    sboxes = []
    for i in range(8): #for each s-box
        #Get the output of _this_ s-box
        sbox_output = sboxes_output[i*4:(i+1)*4] 
        #Get the input to the xor for _this_ s-box
        sbox_xor_input = sboxes_xor_input[i*6:(i+1)*6]   
        
        #Convert the output of the s-box to an integer
        # (the des library stores s-box outputs as integers)
        sbox_value = 0
        for j in range(4): 
            sbox_value |= (int(sbox_output[j]) << (3 - j))

        #Find the 4 s-box inputs that produce the given output
        possible_sbox_inputs = []
        for row in range(4): #Every s-box value appears at least once in every row
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
            #for each bit, undo the XOR operation
            for k in range(len(possible_input)):
                possible_input[k] = possible_input[k] ^ sbox_xor_input[k]

            possible_sbox_inputs.append(possible_input)
        sboxes.append(possible_sbox_inputs)

    return sboxes

#############END LISTING 4

#############LISTING 5
#Use three specially crafted inputs to determine the unique round key R1
# they ensure L1 is 0, and R1 has a special value in it

#these are the published values, but
#  certain inputs fail to be distinguished uniquely by the published values
#special_inputs = ["0000000000000000",
#                  "0000AA000000AA00",
#                  "8220000A8002200A"]

#these values, determined after publication, are better for the attack
special_inputs = ["0000000000000000",
                  "000000AA00000000",
                  "2802000020A20028"]

#Permute the special_inputs to compute the values that will be XORed with the
# round-key R1 before the s-boxes (i.e. compute the value 'a' in Fig. 2)
special_inputs_at_pt_a = []
for i in range(len(special_inputs)):
    after_ip = des.permute(des.hex2bin(special_inputs[i]), des.INITIAL_PERM, 64)
    l0 = after_ip[:32]
    r0 = after_ip[32:]
    r0_expanded = des.permute(r0, des.EXPANSION_FUNC, 48)
    r0_expanded_list = []
    for i in range(48):
        r0_expanded_list.append(int(r0_expanded[i],2))
    special_inputs_at_pt_a.append(r0_expanded_list)

# #For each value in special_inputs_at_pt_a,
# # print it in blocks of 6 bits
# for i in range(len(special_inputs_at_pt_a)):
#     print("Special input %i (%s): " % (i, special_inputs[i]))
#     print("Value at pt. a: ", end="")
#     for j in range(len(special_inputs_at_pt_a[i])):
#         if(j % 6 == 0):
#             print(" ", end="")
#         print("%d" % special_inputs_at_pt_a[i][j], end="")
#     print()
# exit(1)

"""
Special input 0 (0000000000000000): 
Value at pt. a:  000000 000000 000000 000000 000000 000000 000000 000000
Special input 1 (0000AA000000AA00): 
Value at pt. a:  001000 001000 001000 001000 001000 001000 001000 001000
Special input 2 (8220000A8002200A): 
Value at pt. a:  100010 100010 101000 000101 010001 010001 010101 010010
"""

#############END LISTING 5

#############LISTING 6

special_results_after_sbox_pt_c = []
#For each of the 3 special inputs
for special_input in special_inputs:
    #Run 3 rounds of the encryption over the special input (i.e. determine L1, R1)
    (_, scans) = dut.RunEncryptOrDecrypt(special_input, True, 3)

    #Using the scan chain layout we computed earlier, extract the values of L1 and R1 registers
    (l_reg, r_reg) = read_scan_l_r(left_r_scan_indices, right_r_scan_indices, scans[2])
   
    #Undo the P permutation to get the values directly emitted from the SBox 
    # (i.e. the values at point 'c' in Fig. 2)
    special_result = [None]*32
    for i in range(32):
        special_result[des.P_PERM[i]-1] = r_reg[i]
    special_results_after_sbox_pt_c.append(special_result)

# #For each value in special_results_after_sbox_pt_c,
# # print it in blocks of 4 bits
# for i in range(len(special_results_after_sbox_pt_c)):
#     print("Special input %i (%s): " % (i, special_inputs[i]))
#     print("Value at pt. c: ", end="")
#     for j in range(len(special_results_after_sbox_pt_c[i])):
#         if(j % 4 == 0):
#             print(" ", end="")
#         print("%d" % int(special_results_after_sbox_pt_c[i][j]), end="")
#     print()
# exit(1)

#############END LISTING 6

#############LISTING 7

#For each of the s-box special results at point c, 
# use the function sboxes_output_to_possible_inputs() 
# to determine the possible key inputs given the input
# to the xor at point 'a' in Fig. 2.
sbox_possible_key_values = []
for i in range(len(special_results_after_sbox_pt_c)):
    sbox_possible_key_values.append(
        sboxes_output_to_possible_inputs(
            special_results_after_sbox_pt_c[i], special_inputs_at_pt_a[i]
        )
    )

#(Testing purposes only)
#Print the possible key values for each of the s-boxes for each of the 3 special inputs
# for i in range(len(sbox_possible_key_values)):
#     print("Special input %i (%s): " % (i+1, special_inputs[i]))
#     print("Possible key values...")
#     for j in range(len(sbox_possible_key_values[i])):
#         print(" for s-box %i: " % (j+1), end="")
#         for k in range(len(sbox_possible_key_values[i][j])):
#             for l in range(len(sbox_possible_key_values[i][j][k])):
#                 print("%d" % sbox_possible_key_values[i][j][k][l], end="")
#             print(' ', end="")
#         print()
# exit()

#############END LISTING 7

#############LISTING 8

#Each of the sbox_possible_key_values is a list of lists of possible 
# key inputs for that sbox.
# Starting from the first input, remove any possibility that is not present 
# in the other inputs.
# (i.e. find the only input that is in all three sets of sbox possibilities)

possible_roundkey_bits_after_expansion = []
for sbox_index in range(8):
    possible_values = sbox_possible_key_values[0][sbox_index]
    for i in range(1,len(sbox_possible_key_values),1): #start at 1
        other_values = sbox_possible_key_values[i][sbox_index]

        #remove any elements from possible_values that is not present in other_values
        possible_values = [x for x in possible_values if x in other_values]        

    possible_roundkey_bits_after_expansion.append(possible_values)

# #(Testing purposes only)
# #Print the possible key values for each of the s-boxes after this removal step
# # There should only be 1 possible set of bits per section of the key
# print("Possible roundkeys")
# for i in range(len(possible_roundkey_bits_after_expansion)):
#     print("Bits %i-%i have %i possible value: " % (i*8+1,i*8+8,len(possible_roundkey_bits_after_expansion[i])), end="")
#     for j in range(len(possible_roundkey_bits_after_expansion[i])):
#         for k in range(len(possible_roundkey_bits_after_expansion[i][j])):
#             print("%d" % possible_roundkey_bits_after_expansion[i][j][k], end="")
#         print(" ", end="")
#     print()
# exit(1)

#############END LISTING 8

#############LISTING 9

#Convert the set of possible bits per round-key section
# to a set of possible round keys for the round1 key 
# by taking the cartesian product of the possibilities
# Note: there should only be one possible sbox input per sbox at this point,
# so the cartesian product should only return one element.
possible_roundkeys_round1 = []
for components in itertools.product(*possible_roundkey_bits_after_expansion):
    possible_roundkey_round1 = []
    for component in components:
        possible_roundkey_round1.extend(component)
    possible_roundkeys_round1.append(possible_roundkey_round1)

# #(Testing purposes only)
# #Print the possible roundkeys for round1
# for possible_roundkey_round1 in possible_roundkeys_round1:
#     possible_roundkey_val = 0
#     for i in range(48):
#         possible_roundkey_val |= (possible_roundkey_round1[i] << (47-i))
#     print("Possible roundkey 1: %012X" % possible_roundkey_val)

#     # roundkey_1_actual_b = dut.roundkeys_b[0]
#     # roundkey_1_actual_val = 0
#     # for i in range(48):
#     #     roundkey_1_actual_val |= ((roundkey_1_actual_b[i]=="1") << (47 - i))
#     # print("Actual roundkey 1: %012X" % roundkey_1_actual_val)
# exit(1)

#############END LISTING 9

#############LISTING 10

possible_keys = []
#For each possible round1 key, derive every possible key that could have generated it
for possible_roundkey_round1 in possible_roundkeys_round1:
    #First, undo the PC2 permutation
    key1 = [None]*56
    for i in range(48):
        key1[des.KEY_PC2[i]-1] = possible_roundkey_round1[i]
    
    #Now undo the two half-key rotations by
    # right rotating each half of the key
    key1_left = key1[:28]
    key1_right = key1[28:]
    key1_left = key1_left[-1:] + key1_left[:-1]
    key1_right = key1_right[-1:] + key1_right[:-1]
    key1 = key1_left + key1_right

    #Now undo the PC1 permutation
    key = [None]*64
    for i in range(56):
        key[des.KEY_PC1[i]-1] = key1[i]

    #The format of the key is such that it has 64 bits, 
    # but only 48 of them are currently filled with values (the others are 'None')
    # We will create all possible keys by taking the cartesian product
    # of all possible values for the 8 unfilled key bits (ignoring parity bits).
    
    #Prepare the cartesian product by creating a list of lists of 
    # known and possible values for the unfilled key bits.
    combined_key_possibilities = []
    for i in range(64):
        if key[i] == None:
            if (i+1) % 8 != 0:
                combined_key_possibilities.append([0,1]) #Unknown key bit
            else:
                combined_key_possibilities.append([None]) #Parity bit
        else:
            combined_key_possibilities.append([key[i]]) #Known key bit
    
    print("Key possibilities that would generate round key 1:")
    print(combined_key_possibilities)
    
    for components in itertools.product(*combined_key_possibilities):
        #Combine all key bits into a single key
        possible_key_bits = []
        for component in components:
            possible_key_bits.append(component)

        #Calculate the parity bits
        for i in range(8):
            val_bits = possible_key_bits[i*8:(i+1)*8-1]
            parity_bit = 0
            for bit in val_bits:
                parity_bit ^= bit
            possible_key_bits[i*8+7] = parity_bit
        
        #Convert the binary list into a hex string
        key_val = 0
        for i in range(64):
            key_val |= (possible_key_bits[i] << (63-i))
        possible_key_val = '%016X' % key_val

        #Store the possible key
        possible_keys.append(possible_key_val)

print("There are %d possible keys." % len(possible_keys))

#############END LISTING 10

if(dut.key_hex in possible_keys):
   print("key is in the list of possible keys")
else:
   print("key is not in the list of possible keys")

#############LISTING 11

print("Brute-force checking %d possible keys." % len(possible_keys))
for possible_key in possible_keys:
    #print("Checking key %s, it is the possible key: %s" % (possible_key, possible_key == dut.key_hex))
    pos_des = des.DESWithScanChain(force_key=possible_key)
    (test_ciphertext, _) = pos_des.RunEncryptOrDecrypt(test_code)
    if(test_ciphertext == check_ciphertext):
        print("Found the key. It is %s" % possible_key)
        break
    elif possible_key == dut.key_hex:
        print("The key is correct, but the ciphertexts do not match.")
        print("The correct ciphertext is %s" % check_ciphertext)
        print("The incorrect ciphertext is %s" % test_ciphertext)
        break

print("Checking the answer. The embedded secret key was " + dut.key_hex)
if(possible_key == dut.key_hex):
    print("The two keys match, the attack is successful.")

#############END LISTING 11