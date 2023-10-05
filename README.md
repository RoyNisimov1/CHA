# How to use

I already configured the main function, just run it.

# How it works
## Step one: Encipher
The function enciphers each letter with a letter in the shuffle list if it exists there, then shifts the letters in the shuffle list by the ord of c ** 2 each time. 
        
## Step two: Padding
This step adds padding to the cipher text, we also have an amount to shift at the end of it

## Step Three: Keying
We make a copy of the text list (bm in here) and shift everything by the amount to shift

## Step four: XORing
In this step we XOR the ciphertext with our key

## Step five: Final
We join this large list, turn that into an int, and then we return a HASHash object of it

_Notes_:

_Use the hexdigest function to get the value in hex_

*THIS HASH FUNCTION IS PROBABLY NOT THE SAFEST!*

I made it because I was bored, so please use something like Argon2 or Sha512 for real use cases.

PS: I know my code looks bad
