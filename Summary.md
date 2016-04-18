A Simple XOR Chain Encryption Program

# Introduction #

Ok, I dont trust commercial non-open source crap.  Call me paranoid.  But, as a disclaimer, this program is not recommended for seriously secure encryption and is easily hackable.


# Details #

This is a **simple** xor chain encryption program that will encrypt a file, the filename of which must be provided as a command line argument, using a simple CBC encryption algorithm.

Upon execution of the program, the user is prompted to enter a password. If the file is not encrypted, the file will be overwritten with the encrypted file, and a hash of the password will be prepended to the begining of the file. If the file is encrypted, the password is checked against this embedded hash value before decrypting and overwriting the file.

The target file is cached in RAM; the amount of RAM necessary is double the size of the file.

This program is written in c.