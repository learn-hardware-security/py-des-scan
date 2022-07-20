# py-des-scan

This repository contains the source code and Python package for the (under review) 2022 Embedded Systems Week paper "High-Level Approaches to Hardware Security: A Tutorial" case study on DES scan chain attacks (Case Study 1).

### How to use this repository

First, create a folder/file on your computer where you will work.
```
$ mkdir des_scan_attack_study
$ cd des_scan_attack_study
$ touch case_study.py
```

Then, clone this repository.
```
$ git clone https://github.com/learn-hardware-security/py-des-scan py_des_scan
```

Now, in your `case_study.py` you can import the project and test it.
```python
#Useful modules for this tutorial
from typing import *
import itertools

#Import the DESWithScanChain module 
# assuming the py-des-scan GitHub repository is downloaded to a folder called 'py_des_scan'
import py_des_scan.des_scan as des

#Define a random seed for the emulated hardware's key and scan chain
seed = 6

#Instantiate the DES module that we will test/attack
dut = des.DESWithScanChain(seed)

#Do a test run of the DES with a given input 
test_code = "0BADC0DEDEADC0DE"
print("Input: " + test_code)
(check_ciphertext, _) = dut.RunEncryptOrDecrypt(test_code)
print("Ciphertext: " + check_ciphertext)
(plaintext, _) = dut.RunEncryptOrDecrypt(check_ciphertext, do_encrypt=False)
print("Plaintext: " + plaintext)
```
You should see the following output:
```
Input: 0BADC0DEDEADC0DE
Ciphertext: BD3B5B57B1A43D96
Plaintext: 0BADC0DEDEADC0DE
```

The rest of your attack can proceed as noted in the paper.