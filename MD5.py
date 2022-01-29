
import codecs

# S Constants for transformation functions.

S11 = 7
S12 = 12
S13 = 17
S14 = 22

S21 = 5
S22 = 9
S23 = 14
S24 = 20

S31 = 4
S32 = 11
S33 = 16
S34 = 23

S41 = 6
S42 = 10
S43 = 15
S44 = 21

# T Constants for transformation functions.

T = [None for x in range(65)]

T[1] = 0xd76aa478 
T[2] = 0xe8c7b756 
T[3] = 0x242070db 
T[4] = 0xc1bdceee 
T[5] = 0xf57c0faf 
T[6] = 0x4787c62a 
T[7] = 0xa8304613 
T[8] = 0xfd469501 
T[9] = 0x698098d8 
T[10] = 0x8b44f7af 
T[11] = 0xffff5bb1 
T[12] = 0x895cd7be 
T[13] = 0x6b901122 
T[14] = 0xfd987193 
T[15] = 0xa679438e 
T[16] = 0x49b40821 
T[17] = 0xf61e2562 
T[18] = 0xc040b340 
T[19] = 0x265e5a51 
T[20] = 0xe9b6c7aa 
T[21] = 0xd62f105d 
T[22] = 0x2441453  
T[23] = 0xd8a1e681 
T[24] = 0xe7d3fbc8 
T[25] = 0x21e1cde6 
T[26] = 0xc33707d6 
T[27] = 0xf4d50d87 
T[28] = 0x455a14ed 
T[29] = 0xa9e3e905 
T[30] = 0xfcefa3f8 
T[31] = 0x676f02d9 
T[32] = 0x8d2a4c8a 
T[33] = 0xfffa3942 
T[34] = 0x8771f681 
T[35] = 0x6d9d6122  
T[36] = 0xfde5380c 
T[37] = 0xa4beea44 
T[38] = 0x4bdecfa9 
T[39] = 0xf6bb4b60 
T[40] = 0xbebfbc70 
T[41] = 0x289b7ec6 
T[42] = 0xeaa127fa 
T[43] = 0xd4ef3085 
T[44] = 0x04881d05 
T[45] = 0xd9d4d039 
T[46] = 0xe6db99e5 
T[47] = 0x1fa27cf8 
T[48] = 0xc4ac5665 
T[49] = 0xf4292244
T[50] = 0x432aff97
T[51] = 0xab9423a7
T[52] = 0xfc93a039
T[53] = 0x655b59c3
T[54] = 0x8f0ccc92
T[55] = 0xffeff47d
T[56] = 0x85845dd1
T[57] = 0x6fa87e4f
T[58] = 0xfe2ce6e0
T[59] = 0xa3014314
T[60] = 0x4e0811a1
T[61] = 0xf7537e82
T[62] = 0xbd3af235
T[63] = 0x2ad7d2bb
T[64] = 0xeb86d391

PADDING = bytearray(64)
PADDING[0] = 0x80

# Define Four Auxiliary Functions (F, G, H, I) 
def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))

def G(x, y, z): return (((x) & (z)) | ((y) & (~z)))

def H(x, y, z): return ((x) ^ (y) ^ (z))

def I(x, y, z): return((y) ^ ((x) | (~z)))

def ROTATE_LEFT(x, n):
    x = x & 0xffffffff   # make shift unsigned
    return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffff

# FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.

def FF(a, b, c, d, x, s, ac):
    a = a + F ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def GG(a, b, c, d, x, s, ac):
    a = a + G ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def HH(a, b, c, d, x, s, ac):
    a = a + H ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def II(a, b, c, d, x, s, ac):
    a = a + I ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a


class md5(object):
    digest_size = 16  # size of the resulting hash in bytes
    block_size  = 64  # hash algorithm's internal block size

    def __init__(self, string='', state=None, count=0):
        
        self.msgbits = 0
        self.buffer = bytearray(0)

        if state is None:

            self.state = (0x67452301,
                          0xefcdab89,
                          0x98badcfe,
                          0x10325476)            
        else:
            self.state = _decode(state, md5.digest_size)
        if count is not None:
            self.msgbits = count
        if string:
            self.update(string)

    def update(self, input):
        
        # append input to buffer
        try:
            input = input.encode("utf-8")
        except AttributeError:
            pass
        self.buffer = self.buffer + input
        # update message size
        self.msgbits = self.msgbits + (len(input) << 3)

        while len(self.buffer) >= md5.block_size:
            self.state = md5_compress(self.state, self.buffer[:md5.block_size])
            self.buffer = self.buffer[md5.block_size:]

    def digest(self):
       

        _buffer, _msgbits, _state = self.buffer, self.msgbits, self.state
        self.update(padding(self.msgbits))
        result = self.state
        self.buffer, self.msgbits, self.state = _buffer, _msgbits, _state
        return _encode(result, md5.digest_size)

    def hexdigest(self):
        
        return codecs.encode(self.digest(), "hex").decode()

## end of class

def padding(msg_bits):
    
    paddconst = (msg_bits >> 3) % md5.block_size
    paddconst += 8 # the last 8 bytes store the number of bits in the message

    if paddconst < md5.block_size:
        paddlength = md5.block_size - paddconst
    else:
        paddlength = 2 * md5.block_size - paddconst

    # (the last 8 bytes store the number of bits in the message)
    return PADDING[:paddlength] + _encode((msg_bits & 0xffffffff, msg_bits>>32), 8)
    

def md5_compress(state, block):
    
    a, b, c, d = state

    M = _decode(block, md5.block_size)

    #  Round 1
    a = FF (a, b, c, d, M[ 0], S11, T[1]) # 1
    d = FF (d, a, b, c, M[ 1], S12, T[2]) # 2
    c = FF (c, d, a, b, M[ 2], S13, T[3]) # 3
    b = FF (b, c, d, a, M[ 3], S14, T[4]) # 4
    a = FF (a, b, c, d, M[ 4], S11, T[5]) # 5
    d = FF (d, a, b, c, M[ 5], S12, T[6]) # 6
    c = FF (c, d, a, b, M[ 6], S13, T[7]) # 7
    b = FF (b, c, d, a, M[ 7], S14, T[8]) # 8
    a = FF (a, b, c, d, M[ 8], S11, T[9]) # 9
    d = FF (d, a, b, c, M[ 9], S12, T[10]) # 10
    c = FF (c, d, a, b, M[10], S13, T[11]) # 11
    b = FF (b, c, d, a, M[11], S14, T[12]) # 12
    a = FF (a, b, c, d, M[12], S11, T[13]) # 13
    d = FF (d, a, b, c, M[13], S12, T[14]) # 14
    c = FF (c, d, a, b, M[14], S13, T[15]) # 15
    b = FF (b, c, d, a, M[15], S14, T[16]) # 16

    # Round 2
    a = GG (a, b, c, d, M[ 1], S21, T[17]) # 17
    d = GG (d, a, b, c, M[ 6], S22, T[18]) # 18
    c = GG (c, d, a, b, M[11], S23, T[19]) # 19
    b = GG (b, c, d, a, M[ 0], S24, T[20]) # 20
    a = GG (a, b, c, d, M[ 5], S21, T[21]) # 21
    d = GG (d, a, b, c, M[10], S22, T[22]) # 22
    c = GG (c, d, a, b, M[15], S23, T[23]) # 23
    b = GG (b, c, d, a, M[ 4], S24, T[24]) # 24
    a = GG (a, b, c, d, M[ 9], S21, T[25]) # 25
    d = GG (d, a, b, c, M[14], S22, T[26]) # 26
    c = GG (c, d, a, b, M[ 3], S23, T[27]) # 27
    b = GG (b, c, d, a, M[ 8], S24, T[28]) # 28
    a = GG (a, b, c, d, M[13], S21, T[29]) # 29
    d = GG (d, a, b, c, M[ 2], S22, T[30]) # 30
    c = GG (c, d, a, b, M[ 7], S23, T[31]) # 31
    b = GG (b, c, d, a, M[12], S24, T[32]) # 32

    # Round 3
    a = HH (a, b, c, d, M[ 5], S31, T[33]) # 33
    d = HH (d, a, b, c, M[ 8], S32, T[34]) # 34
    c = HH (c, d, a, b, M[11], S33, T[35]) # 35
    b = HH (b, c, d, a, M[14], S34, T[36]) # 36
    a = HH (a, b, c, d, M[ 1], S31, T[37]) # 37
    d = HH (d, a, b, c, M[ 4], S32, T[38]) # 38
    c = HH (c, d, a, b, M[ 7], S33, T[39]) # 39
    b = HH (b, c, d, a, M[10], S34, T[40]) # 40
    a = HH (a, b, c, d, M[13], S31, T[41]) # 41
    d = HH (d, a, b, c, M[ 0], S32, T[42]) # 42
    c = HH (c, d, a, b, M[ 3], S33, T[43]) # 43
    b = HH (b, c, d, a, M[ 6], S34, T[44]) # 44
    a = HH (a, b, c, d, M[ 9], S31, T[45]) # 45
    d = HH (d, a, b, c, M[12], S32, T[46]) # 46
    c = HH (c, d, a, b, M[15], S33, T[47]) # 47
    b = HH (b, c, d, a, M[ 2], S34, T[48]) # 48

    # Round 4
    a = II (a, b, c, d, M[ 0], S41, T[49]) # 49
    d = II (d, a, b, c, M[ 7], S42, T[50]) # 50
    c = II (c, d, a, b, M[14], S43, T[51]) # 51
    b = II (b, c, d, a, M[ 5], S44, T[52]) # 52
    a = II (a, b, c, d, M[12], S41, T[53]) # 53
    d = II (d, a, b, c, M[ 3], S42, T[54]) # 54
    c = II (c, d, a, b, M[10], S43, T[55]) # 55
    b = II (b, c, d, a, M[ 1], S44, T[56]) # 56
    a = II (a, b, c, d, M[ 8], S41, T[57]) # 57
    d = II (d, a, b, c, M[15], S42, T[58]) # 58
    c = II (c, d, a, b, M[ 6], S43, T[59]) # 59
    b = II (b, c, d, a, M[13], S44, T[60]) # 60
    a = II (a, b, c, d, M[ 4], S41, T[61]) # 61
    d = II (d, a, b, c, M[11], S42, T[62]) # 62
    c = II (c, d, a, b, M[ 2], S43, T[63]) # 63
    b = II (b, c, d, a, M[ 9], S44, T[64]) # 64

    return (0xffffffff & (state[0] + a),
            0xffffffff & (state[1] + b),
            0xffffffff & (state[2] + c),
            0xffffffff & (state[3] + d))


import struct

# Encodes values to a series of little-endian unsigned 32bit integers
# Returns a bytes object
def _encode(input, length):
    k = length >> 2
    res = struct.pack("<%iI" % k, *tuple(input[:k]))
    return res

# Decodes values from a series of little-endian unsigned 32bit integers
# Returns a list
def _decode(input, length):
    k = length >> 2
    res = struct.unpack("<%iI" % k, input[:length])
    return list(res)

def input(input=""):
    
    print ("The input message is: ", input)
    print("The message digest of the above input is: ",repr(md5(input).hexdigest()))
    

if __name__=="__main__":
    input("Today is 22nd of December 2021")

