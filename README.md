KeygenMe "Psychic powers or brute strength your choice" ([task source](https://forum.tuts4you.com/topic/37904-keygenme-01-psychic-powers-or-brute-strength-your-choice)) solution

###Program flow explanation

program accept:
	```5 <= len(NAME) < 256
	16 <= len(KEY) < 256```
it lowercase all `NAME` chars, and  delete from name all non `a`-`z` chars. Then it delete all non base64-alphabet chars from KEY, and check if `len(KEY) == 16`
Lets consider `NAME` as string with length 5 or greater, and which consist from 'a'-'z' chars.
Lets consider `KEY` as string with length 16, and which consist from base64-alphabet chars (`+,/',0-9,A-Z,a-z`).

Then program compare if NAME:KEY pair is not 
"lostit":"_RY5obY7IduF4Se2T_"
"tutsyou":"_RkIomczPYHNrJoCA_"
which are valid NAME:KEY pairs, but for some reason blacklisted in such way.

Now your program begin to calculate different hashes and make different CHECKS:

**FIRST HASH**: hash retrived from KEY, lets give him a name K_hash_1. K_hash_1 is 12 byte hash, each 4 bytes of KEY converted to 3 bytes of K_hash_1 . Below figure show this transformation:
