# Hashing use cases

Storing passwords with salt

# How to use

Both functions will return a hash object, call hexdigest

I made a main func where you can test both:

        while True:
        m = input("Message\n")
        mode = input('Mode:\n HAS\n HASS\n').lower()
        if mode == 'hass':
            h = HASHash.HASS(m)

        else:
            h = HASHash.HAS(m)
            # You can put the length that you want in hexdigest(n_bits), for 512 put 128, 1/4
        n_bits = input('You can put the length that you want in hexdigest(n_bits), for 512 put 128, 1/4:\n')
        if n_bits.isspace() or n_bits == '': n_bits = 128
        n_bits = int(n_bits)
        h = h.hexdigest(n_bits)
        print(f"My hash:\n{h}")
        h2 = hashlib.sha512(m.encode()).hexdigest()
        print(f"Sha512:\n{h2}")

Using HAS:

    h = HASHash.HAS(message)
    # for digesting use hexdigest with 128 for 512 bits
    print(h.hexdigest(128))

Using HASS:

    h = HASHash.HASS(message)
    # for digesting use hexdigest with 128 for 512 bits
    print(h.hexdigest(128))


# How HAS works
## Step One: Encipher
The function enciphers each letter with a letter in the shuffle list if it exists there, then shifts the letters in the shuffle list by the ord of c ** 2 each time. 

        shaffle_list = ['p', 'P', '{', 'D', '=', 'F', 'l', 'f', '@', 'b', 'k', '5', 'M', 'H', ':', 'U', '[', 'A', 'u', '`', 'w', "'", '1', 'S', '~', '^', '"', 'L', '3', '#', 'C', '!', '\\', 'a', 'y', 'Q', 'X', 'v', '4', '2', 'V', 'g', 'h', 'n', 'R', 'B', 'I', '|', 'O', 'W', 'd', ' ', 'T', 'G', '/', 'o', '&', ']', 'Y', 'E', '<', 'z', '?', '$', '9', 't', '}', '7', 'm', ';', '.', 's', '-', '0', 'r', ')', '8', '+', 'Z', ',', '%', 'e', 'q', '6', 'N', '>', 'x', 'c', '*', 'K', 'J', 'i', '(', 'j', '_']
        for c in message:
            try:
                index = en.index(c)
                om.append(shaffle_list[index])
            except ValueError:
                om.append(c)
            for i in range(0, ord(c)**2):
                first = shaffle_list.pop(0)
                shaffle_list.append(first)

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

## Step Five: Final
We join this large list, turn that into an int, and then we return a HASHash object of it

        s = ''
        for string in s_xored:
            s += string.strip("-")
        last_int = int(s)
        return HASHash(last_int)


# CHA - Customizable-Hashing-Algorithm
CHA works the same way as HAS, but customizable. so I'll only talk about the customization.

## message
The plaintext that enters the function.

## padding
The padding as a byte string separated by a space, like : ```'01110011 00110011 11000110'```.
this will be appended to the message
## shaffle_list
The letter shuffle list [Check the encipher step in the HAS](#How-HAS-works)

## size_limit_of_0
how many 0 are allowed

# How HASS works
## Step One: shuffling
Foreach letter we:
    
1. Switch the letter for the one in the shuffle list
2. Shift the shuffle list by the letter's ord


        chars = st.ascii_letters + st.digits + st.punctuation + ' '
        shuffled = ['9', 'n', '5', '<', '0', 'W', '_', '\\', '2', 'e', '(', 'u', "'", 'f', '~', 'y', 'v', 'U', 'O', 'N', 'm', 'F', '[', '+', 'i', 'Y', 'T', ':', 'B', 'Q', 'R', 'I', 'z', '?', 'L', 'j', '1', '*', ' ', 'J', 'q', 'r', 'X', '%', 'Z', '{', '7', 'h', 's', ';', '-', '!', 'b', 'M', 'k', 'c', '|', 'd', '&', 'V', 'l', 'P', '"', 'C', '@', 'H', 'a', '4', 'w', '=', 'x', '.', ',', '8', '6', 'G', 'g', 'A', '`', 't', ')', '#', '^', '/', '3', 'E', '$', '}', 'o', 'p', '>', 'D', 'S', 'K', ']']
        return_str = ''
        for ch in message:
            if ch not in shuffled or ch not in chars: continue
            index = chars.index(ch)
            return_str += shuffled[index]
            for i in range(0, ord(ch)):
                first = shuffled.pop(0)
                shuffled.append(first)

## Step Two: turning into int
We make the ciphertext list be a string, and then turning into int

        s = ''
        for c in return_str:
            s += str(ord(c)**ord(c))
        if len(s) > 0:
            last = int(s)
        else:
            last = 1
        return HASHash(last)

### _*Note*_
This function will not return a fixed length, and will only work on english letters for now


_Notes_:

_Use the hexdigest function to get the value in hex_

*THIS HASH FUNCTION IS PROBABLY NOT THE SAFEST!*

I made it because I was bored, so please use something like Argon2 or Sha512 for real use cases.

Also, there might already be a similar hashing function that I don't know of

PS: I know my code looks bad
