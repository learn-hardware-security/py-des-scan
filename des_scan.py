"""This file is a pure python implementation of a DES algorithm with an embedded scan chain."""

import random

# Hexadecimal to binary conversion
def hex2bin(s):
    mp = {'0' : "0000",
          '1' : "0001",
          '2' : "0010",
          '3' : "0011",
          '4' : "0100",
          '5' : "0101",
          '6' : "0110",
          '7' : "0111",
          '8' : "1000",
          '9' : "1001",
          'A' : "1010",
          'B' : "1011",
          'C' : "1100",
          'D' : "1101",
          'E' : "1110",
          'F' : "1111" }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin
     
# Binary to hexadecimal conversion
def bin2hex(s):
    mp = {"0000" : '0',
          "0001" : '1',
          "0010" : '2',
          "0011" : '3',
          "0100" : '4',
          "0101" : '5',
          "0110" : '6',
          "0111" : '7',
          "1000" : '8',
          "1001" : '9',
          "1010" : 'A',
          "1011" : 'B',
          "1100" : 'C',
          "1101" : 'D',
          "1110" : 'E',
          "1111" : 'F' }
    hex = ""
    for i in range(0,len(s),4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]
         
    return hex
 
# Binary to decimal conversion
def bin2dec(binary):
       
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal
 
# Decimal to binary conversion
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res)%4 != 0):
        div = len(res) / 4
        div = int(div)
        counter =(4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res
 
# Permute function to rearrange the bits
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation
 
# shifting the bits towards left by nth shifts
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1,len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k   
 
# calculating xow of two strings of binary number a and b
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans
 
# Table of Position of 64 bits at initial level: Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
 
# Expansion D-box Table
exp_d = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5,
         6 , 7 , 8 , 9 , 8 , 9 , 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1 ]
 
# Straight Permutation Table
per = [ 16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25 ]
 
# S-box Table
sbox =  [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],
            
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
           [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]],
   
         [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
           [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
           [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]],
       
          [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
           [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
           [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ],
        
          [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
           [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
           [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]],
       
         [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
           [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],
         
          [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
           [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],
        
         [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]
   
# Final Permutation Table
final_perm = [ 40, 8, 48, 16, 56, 24, 64, 32,
               39, 7, 47, 15, 55, 23, 63, 31,
               38, 6, 46, 14, 54, 22, 62, 30,
               37, 5, 45, 13, 53, 21, 61, 29,
               36, 4, 44, 12, 52, 20, 60, 28,
               35, 3, 43, 11, 51, 19, 59, 27,
               34, 2, 42, 10, 50, 18, 58, 26,
               33, 1, 41, 9, 49, 17, 57, 25 ]

# --PC1 key permutation and parity bit drop table
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4 ]

# key shifting, contains number of bit shifts for that round
shift_table = [1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1 ]
 
# Key- PC2 Compression Table : Compression of key from 56 bits to 48 bits
key_comp = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32 ]

class DESWithScanChain(): 
    def __init__(self, seed):
        """Define a DES instance with a randomly generated scan chain and randomly generated key."""
        #define 32-bit left and right binary registers
        self.left_b = "00000000000000000000000000000000"
        self.right_b = "00000000000000000000000000000000"

        #define 64-bit input and output binary registers
        self.input_b = "0000000000000000000000000000000000000000000000000000000000000000"
        self.output_b = "0000000000000000000000000000000000000000000000000000000000000000"

        #create the source of random
        rnd = random.Random(seed)

        #create a randomly generated scan chain
        self.scan_chain_order = list(range(192)) #randomize the scan chain
        rnd.shuffle(self.scan_chain_order)

        #create a randomly generated key (16 hexadecimal digits)
        self.key_hex = ""
        for i in range(16):
            self.key_hex += hex(rnd.randint(0,15))[2:]
        self.key_hex = self.key_hex.upper()

        self.roundkeys_b = []
        self.DetermineSubkeys()

    def GetScanChainString(self):
        """Computes the scan chain as a string and returns it"""
        #registers in scan chain are INPUT(64), R(32), L(32), and output (64)
	    #64*3 = 192
	    #63:0 - INPUT
	    #95:64 - RIGHT
	    #128:96 - LEFT
	    #192:129 - OUTPUT
        scan_chain = ""
        for i in range(192):
            scan_bit = self.scan_chain_order[i]
            if scan_bit < 64:
                scan_chain += self.input_b[scan_bit]
            elif scan_bit < 96:
                scan_chain += self.right_b[scan_bit-64]
            elif scan_bit < 128:
                scan_chain += self.left_b[scan_bit-96]
            else:
                scan_chain += self.output_b[scan_bit-128]

        return scan_chain
    
    def DetermineSubkeys(self):
        # Key generation
        # --hex to binary
        key = hex2bin(self.key_hex)
 
        # getting 56 bit key from 64 bit using the parity bits
        key = permute(key, keyp, 56)
        print("Key after initial permutation", bin2hex(key))
 
        # Splitting
        left = key[0:28]    # rkb for RoundKeys in binary
        right = key[28:56]  # rk for RoundKeys in hexadecimal
 
        for i in range(0, 16):
            # Shifting the bits by nth shifts by checking from shift table
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            #print("Left: ", left)
            #print("Right:", right)
            
            # Combination of left and right string
            combine_str = left + right
            #print("Combine", combine_str)
            
            # Compression of key from 56 to 48 bits
            round_key = permute(combine_str, key_comp, 48)
            #print("Round_key", round_key)
        
            self.roundkeys_b.append(round_key)

    def LoadInputRegister(self, input):
        """Load the input to be encrypted or decrypted.
        Should be a 16-character hexadecimal string."""
        self.input_b = hex2bin(input)

    def LoadOutputRegister(self):
        # Concatenate left and right registers
        combine = self.left_b + self.right_b
     
        # Final permutation: final rearranging of bits to get cipher text
        self.output_b = permute(combine, final_perm, 64)

    def RunRound(self, round_num, do_encrypt = True):
        #  Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(self.right_b, exp_d, 48)
        # XOR RoundKey and right_expanded
        if(do_encrypt):
            xor_x = xor(right_expanded, self.roundkeys_b[round_num])
        else:
            xor_x = xor(right_expanded, self.roundkeys_b[15-round_num])
        
        # S-box substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)
 
        # Straight D-box: After substituting rearranging the bits 
        sbox_str = permute(sbox_str, per, 32)

        # XOR left and sbox_str
        result = xor(self.left_b, sbox_str)
        
        self.left_b = result
         
        # Swapper
        if(round_num != 15):
            self.left_b, self.right_b = self.right_b, self.left_b
        
        #print("Round ", round_num + 1, bin2hex(self.left_b,), " ", bin2hex(self.right_b), " ", bin2hex(self.roundkeys_b[round_num]))

    def EncryptOrDecrypt64BitInput(self, plaintext, do_encrypt = True, num_rounds = 18):
        scan_chains = []
        if num_rounds > 0:
            self.LoadInputRegister(plaintext)
            scan_chains.append(self.GetScanChainString())

        if num_rounds>1:
            # Initial Permutation
            data_after_ip = permute(self.input_b, initial_perm, 64)
            #print("After initial permutation", bin2hex(pt))
            # Splitting
            self.left_b = data_after_ip[0:32]
            self.right_b = data_after_ip[32:64]
            scan_chains.append(self.GetScanChainString())
    
        if num_rounds>2:
            for i in range(0, num_rounds-2):
                self.RunRound(i, do_encrypt)
                scan_chains.append(self.GetScanChainString())
        
        if num_rounds>17:
            self.LoadOutputRegister()
            scan_chains.append(self.GetScanChainString())
        
        return (bin2hex(self.output_b), scan_chains)

if __name__ == "__main__":        
    seed = 100
    pt = "0000000000000004"

    dut = DESWithScanChain(seed)
    print("Key: ", dut.key_hex)
    print("Input: ", pt)

    (cipher, scans) = dut.EncryptOrDecrypt64BitInput(pt, True, 18)
    
    print("Cipher Text : ", cipher)
    
    print("Decryption")
    (plain, scans) = dut.EncryptOrDecrypt64BitInput(cipher, False, 18)
    print("Plain Text : ", plain)
    