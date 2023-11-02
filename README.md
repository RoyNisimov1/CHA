# Hashing use cases

1. Detecting duplicated records.
2. Locating points that are near each other.
3. Verifying message integrity.
4. Verifying passwords.

# How to use


I made a main func where you can test, but the syntax is:
```
CHAObject.RA(message).hexdigest(128)
```



# How RA works
## Step One: Encipher
The function enciphers each letter with a letter in the shuffle list if it exists there, then shifts the letters in the shuffle list by the ord of c ** ord c each time. 

                    for c in message:
                for i in range(0, pow(ord(c), ord(c), len(shaffle_list))):
                    first = shaffle_list.pop(0)
                    shaffle_list.append(first)
                if c in characters:
                    index = characters.index(c)
                    om.append(shaffle_list[index])
                else:
                    om.append(c)

## Step Two: Padding
This step adds padding to the cipher text, we also have an amount to shift at the end of it

        bm = [format(ord(c), 'b') for c in om]
        amount_to_shift = len(padding_list) - len(bm)
        if amount_to_shift <= 0: amount_to_shift *= -1
        shift_must = ord(om[0]) if len(om) > 0 else 153
        amount_to_shift += shift_must
        for i, b in enumerate(padding_list):
            bm.append(b)

## Step Three: Keying
We make a copy of the text list (bm in here) and shift everything by the amount to shift

        key = bm.copy()
        for i in range(0, amount_to_shift):
            first = key.pop(0)
            key.append(first)
        if key == bm:
            first = key.pop(0)
            key.append(first)

## Step Four: XORing
In this step we XOR the ciphertext with our key

        bm = list(int(c, 2) for c in bm)
        key = list(int(c, 2) for c in key)
        xored = []
        for i in range(len(bm)):
            xored.append(bm[i] ^ key[i])
        s_xored = [str(n) for n in xored]
## Step Five: Repeat and shift padding
We shift the padding by ```amount_to_shift**amount_to_shift % len(padding_list)```

This process repeat 16 times using the "s" as the new message

## Step Six: Final
We join this large list, turn that into an int, and then we return a HASHash object of it

        s = ''
        for string in s_xored:
            s += string.strip("-")
        last_int = int(s)
        return HASHash(last_int)


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

# CHAB
Like CHA but the message is in bytes



# Creating your own algorithm using HashMaker

## RandomShaffle
This function will help you make your own random shuffled charset (```random.shuffle(letters)``` but with built-in langs)
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
        padding, shuffle_list, size, rep, char_set, smio = HASHash.get_HAS_args()
        return HASHash.CHAB(b,padding,shuffle_list, 128, 16, '', 153)
    s = input("Enter an input:\n").encode()
    e = Feistel64.DE(s,  8, fCHA)
    print(e)
    d = Feistel64.DE(e,  8,fCHA, 'd')
    print(d)
```

to make your own:

## define a function
define a function using this template
```
    def fCHA(b):
        padding, shuffle_list, size, rep, char_set, smio = HASHash.get_HAS_args()
        return HASHash.CHAB(b,padding,shuffle_list, 128, 16, '', 153)
```

the function needs to return bytes, here we're using CHAB with the RA args. 

## Call DE

then the Feistel function uses 64 bits everytime, I configed the DE function on the Feistel64 class
to do this automatically.
### mode 'e'
this will return a list of hexes
### mode 'd'
will return the string

[Feistel Cipher - Computerphile](https://www.youtube.com/watch?v=FGhj3CGxl8I)

# *_Notes_*:

1. _Use the hexdigest function to get the value in hex_

2. *THIS HASH FUNCTION IS PROBABLY NOT THE SAFEST!*

3. I made it because I was bored, so please use something like Argon2 or Sha512 for real use cases.

4. Also, there might already be a similar hashing function that I don't know of

5. In the HashMaker there is a chance that some padding or shuffle_key have a backdoor in them (Though not probable). 

PS: I know my code looks bad
