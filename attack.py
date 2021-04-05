#!usr/bin/env python3

from oracle import encrypt, oracle, BLOCK_SIZE

# utility method to split real ciphertext into a list of blocks
def blockify(ciphertext):

    # calculate number of blocks
    num_blocks = len(ciphertext)/16

    # make list of empty lists
    blocks = [[]] * num_blocks

    # break ciphertext into blocks
    for i in range(num_blocks):
        blocks[i] = ciphertext[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]

    return blocks

# utlity method to query oracle
# takes fakeciphertext block and real ciphertext block and combines them
# queries oracle, returns true if oracle returns true
def query_oracle(fake, realblock):

    # make a string that contains the fakeciphertext and the real ciphertext block
    # this is C1'C2
    # this is a string with 32 characters
    totalciphertext = ''.join(fake) + realblock

    return(oracle(totalciphertext))

def attack(ciphertext):
    #blocks is a list of lists, where each internal list is a block from the cipher
    blocks = blockify(ciphertext)
    
    #c1 is the second block -- first block is the initialization vector
    c1 = blocks[1]
    #the block we are doing to decrypt
    c2 = blocks[2]

    #initalize fake ciphertext to random string of 16 z's. C1'
    fakeCipherText = list("zzzzzzzzzzzzzzzz")

    #initialize plaintext. these will get edited as the message gets decoded. P2
    plainText = list("0000000000000000")

    intermediate = list("iiiiiiiiiiiiiiii")
    hold = ''

    for c in range(1, BLOCK_SIZE+1):
        for v in range(0,256):
            fakeCipherText[-c] = chr(v) #C1'[c]. set last value in fakeciphertext to v
            if (query_oracle(fakeCipherText, c2)):
                intermediate[-c] = c ^ v
                plainText[-c] = chr(intermediate[-c] ^ ord(c1[-c]))
                print(plainText)
                for k in range(BLOCK_SIZE-c, BLOCK_SIZE):
                    hold = ''
                
    return 0

# test attack by encrypting a message and then calling attack method
def test_attack():

    message = "Sloths are incredibly awesome"
    output = attack(encrypt(message))
    print(output)
    
if __name__ == '__main__':
    test_attack()

