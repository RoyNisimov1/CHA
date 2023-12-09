# READ ME
This was made for fun and learning cryptography and python.
Everything here is not for real use-cases.
Keep in mind that the functions here are probably insecure. 
They went through 0 security checks, and were made without thinking of the security side of things.


# Hashing use cases

1. Detecting duplicated records.
2. Locating points that are near each other.
3. Verifying message integrity.
4. Verifying passwords.

# Installation
## pip

``` 
pip install cha-hashing
```

# how to use
import CHA *
```python
from CHA import FeistelN
from CHA import CHAObject
from CHA import HashMaker
from CHA import Piranha
from CHA import PEMFile
```
or just 
```
from CHA import *
```


# How RA works
## The shuffle algorithm
```python
def shuffle(to_shuffle_list: list):
    to_shuffle_list = to_shuffle_list.copy()
    to_append_size = to_shuffle_list[0]
    a = []
    for i1 in range(to_append_size % len(to_shuffle_list)):
        a.append(to_shuffle_list.pop(0))
    to_shuffle_list.reverse()
    for i2 in a:
        to_shuffle_list.append(i2)
    e = []
    for i3, ch in enumerate(to_shuffle_list):
        if i3 % 2 == 0:
            e.append(to_shuffle_list.pop(i3))
    for i4 in e:
        to_shuffle_list.append(i4)
    return to_shuffle_list
```
## Step One: Encipher
The function enciphers each letter with a letter in the shuffle list if it exists there, then shifts the letters in the shuffle list by the ord of c ** ord c each time. 
``` 
for c in message:
    for i in range(0, pow(ord(c), ord(c), len(shuffle_list))):
        first = shuffle_list.pop(0)
        shuffle_list.append(first)
    ord_shuffle_list = [ord(c) for c in shuffle_list]
    shuffled = shuffle(ord_shuffle_list)
    shuffle_list = [chr(c) for c in shuffled]
    if c in characters and c in shuffle_list:
        index = characters.index(c)
        original_message.append(shuffle_list[index])
    else:
        original_message.append(c)
```

## Step Two: Padding

``` 
binary_formatted_message = [format(ord(c), 'b') for c in original_message]

            amount_to_shift = len(padding_list) - len(binary_formatted_message)
            if amount_to_shift <= 0: amount_to_shift *= -1
            shift_must = ord(original_message[0]) if len(original_message) > 0 else shift_must_if_om0
            amount_to_shift += shift_must
            binary_formatted_message.extend(padding_list)
```

## Step Three: Keying

``` 
key = binary_formatted_message.copy()
            for i in range(0, amount_to_shift):
                if times % rev_every == 0:
                    key.reverse()
                first = key.pop(0)
                key.append(first)
            if key == binary_formatted_message:
                first = key.pop(0)
                key.append(first)
```

## Step Four: XORing
In this step we XOR the ciphertext with our key

```
binary_formatted_message = list(int(c, 2) for c in binary_formatted_message)
key = list(int(c, 2) for c in key)
xored = []
for i in range(len(binary_formatted_message)):
    xored.append(binary_formatted_message[i] ^ key[i])
```
## Step Five: Repeat and shift padding

``` 
binary_formatted_message = list(int(c, 2) for c in binary_formatted_message)
key = list(int(c, 2) for c in key)
xored = []
for i in range(len(binary_formatted_message)):
    xored.append(binary_formatted_message[i] ^ key[i])
```

## Step Six: Final
We join this large list, turn that into an int, and then we return a CHAObject object of it
``` 
s_xored = [str(n) for n in xored]
s = ''
for string in s_xored:
    s += string.strip("-")
s = s[0:size_limit_of_0]
for i in range(pow(amount_to_shift, amount_to_shift, len(padding_list))):
    intL = [int(c, 2) for c in padding_list]
    padding_list = shuffle(intL)
    padding_list = [format(c, 'b') for c in padding_list]
message = s
```


# CHA - Customizable Hashing Algorithm
CHA works the same way as RA, but customizable. so I'll only talk about the customization.

## message
The plaintext that enters the function.

## padding
The padding as a byte string separated by a space, like : ```'01110011 00110011 11000110'```.
this will be appended to the message
## shaffle_list
The letter shuffle list [Check the encipher step in the RA](#How-RA-works)

## size_limit_of_0
how many 0 are allowed

## rep
number of repetitions

## char_set
Additional chars used in the shuffle_list

## shift_must_if_om0
```shift_must = ord(om[0]) if len(om) > 0 else shift_must_if_om0```

## rev_every
Will preform some additional tasks with every time % $rev_every == 0

# CHAB
Like CHA but the message is in bytes

# HMAC
Syntax for hmac:
```python
from CHA import FeistelN
from CHA import CHAFHMAC
# our secret key:

secret = b'test'
# message
msg = b'secret msg'
# creating a hmac obj
hmac_obj = CHAFHMAC(secret, func=FeistelN.fRAB_with_nonce(secret))
hmac_obj.update(msg)
# getting a mac
mac = hmac_obj.hexdigest()
print(mac)
# verifying a mac
print(hmac_obj.verify(mac))
```

# Creating your own algorithm using HashMaker

## RandomShaffle
This function will help you make your own random shuffled charset (```secrets.SystemRandom().shuffle(letters)``` but with built-in langs)
returns a string

## RandomBits
This function will help you make your own random bits.
returns a string or a list

```
how_many:
how many groups of bits do you want.
```
```
group:
how many in one group, 8 for a byte
```
```
how_to_format:
Can be " " or "l". 
"l" for a list.
" " for a " ".join(bits)
```
## get_CHA_args
This function will print the syntax needed. and return the padding, and shuffle key.

### _Note_
There is a chance that some padding or shuffle_key have a backdoor in them (I don't know if there really is, but probably). 

# Encryption with CHA

CHA can be also used as an encryption function using the feistel cipher (see CHAF)


for example:
```
    def fCHA(b):
        padding, shuffle_list, size, rep, char_set, smio = CHAObject.get_RA_args()
        return CHAObject.CHAB(b,padding,shuffle_list, 128, 16, '', 153)
    s = input("Enter an input:\n").encode()
    e = FeistelN().DE(s,  8, fCHA)
    print(e)
    d = FeistelN().DE(e,  8,fCHA, 'd')
    print(d)
```

to make your own:

## define a function
define a function using this template
```
    def fCHA(b):
        padding, shuffle_list, size, rep, char_set, smio = CHAObject.get_RA_args()
        return CHAObject.CHAB(b,padding,shuffle_list, 128, 16, '', 153)
```

the function needs to return bytes, here we're using CHAB with the RA args. 

## Call DE

then the Feistel function uses 64 bits everytime, I configed the DE function on the FeistelN class
to do this automatically.
### mode 'e'
this will return a list of hexes
### mode 'd'
will return the string

[Feistel Cipher - Computerphile](https://www.youtube.com/watch?v=FGhj3CGxl8I)

# BlackFrog
This is an asymmetric encryption algorithm
``` 
Key generation:
—---------------------------------------------------------------

Let n = large prime number

Pick e such that gcd(e,n) == 1 and e < n and e is prime
d = e**-1 % n
N = n * e * random
E = e**d % N
D = d**d % n

Public key: {E,N}
Private key: {n,d,e,D}

Encryption:
—---------------------------------------------------------------

ciphertext = message*E % N

Decryption:
—---------------------------------------------------------------
message = ciphertext*D % n
```
## Generate keys
returns two keys, one public, one private

## Encrypt

Encrypts bytes with public key and returns cipher text as bytes

## Decrypt

Decrypt bytes with private key and returns message text as bytes


# Piranha
I made this cipher using the RAB-Feistel network.

I made this to learn about [modes of operation](https://www.youtube.com/watch?v=Rk0NIQfEXBA).

Right now the available modes are:
* ECB
* CBC
* CTR
* EAA (My Encrypt and Authenticate, not EAX)

``` 
    key = b"super secret key"
    msg = b'Test message'
    # EBC
    cipher = Piranha(key, Piranha.EBC)
    c = cipher.encrypt(msg)
    print(c)
    cipher = Piranha(key, Piranha.EBC)
    m = cipher.decrypt(c)
    print(m)

    # CBC
    cipher = Piranha(key, Piranha.CBC)
    paddedMsg = Piranha.pad(msg, Piranha.BlockSize)
    c = cipher.encrypt(paddedMsg)
    print(c)
    cipher = Piranha(key, Piranha.CBC, iv=cipher.iv)
    m = Piranha.unpad(cipher.decrypt(c))
    print(m)

    # CTR
    cipher = Piranha(key, Piranha.CTR)
    paddedMsg = Piranha.pad(msg, Piranha.BlockSize)
    c = cipher.encrypt(paddedMsg)
    print(c)
    cipher = Piranha(key, Piranha.CTR, iv=cipher.iv)
    m = Piranha.unpad(cipher.decrypt(c))
    
    # EAA
    key = b"key"
    m = Piranha.pad(b'test')
    cipher = Piranha(key, Piranha.EAA, data=m)
    a = cipher.encrypt(m)
    print(a)
    cipher = Piranha(key, Piranha.EAA, iv=cipher.iv, data=a)
    print(Piranha.unpad(cipher.decrypt(a)))
```



# *_Notes_*:

<font color=red size=10>**This is insecure! I made everything for fun and learning! Do not use in real usecases**
</font>

PS: I know my code looks bad
