# Linear & Differential Cryptanalysis

This repository contains code that implements linear and differential cryptanalysis
of a simple substitution-permutation network cipher, following and expanding on the
contents of Howard M. Heys excellent
[_Tutorial on Linear and Differential Cryptoanalysis_](https://www.cs.bc.edu/~straubin/crypto2017/heys.pdf).

## The Cipher
[cipher.py](src/cipher.py) contains an implementation of the simple cipher used 
for the cryptanalysis. Although simple, it uses a 10 byte key split into 5 round keys,
each independent of each other. If chosen randomly, brute forcing this key would 
require trying up to 2^80 different keys (actually somewhat less since some keys 
are equivalent, e.g. c7e69**0**b1**f**1ac05b15481 and c7e69**e**b1**b**1ac05b15481). 
While certainly feasible with enough hardware, brute forcing the cipher key 
is still time-consuming and costly. However, the cipher has poor 
differential and linear properties which allows us to break the key in minutes.

## Differential Cryptanalysis
[differential.py](src/differential.py) contains a `DifferentialAnalyser` class 
that can completely break the cipher key with greater than 50% probability.
By analysing bit differences in pairs of output ciphertexts resulting from the 
encryption of input plaintexts with specific bit differences, it is possible 
to infer the most likely round key and peel the cipher back round by round. 
It is a chosen plaintext attack, meaning that in order to work we must have 
access to an encryption oracle. The given implementation requires about 4000 
interactions with this oracle to have a good chance to break the key.

## Linear Cryptanalysis
[linear.py](src/linear.py) contains a `LinearAnalyzer` class that can break the 
last round key used by the cipher with greater than 50% probability, and which 
could be further extended to break the whole cipher key. This is done
by identifying linear approximations of the cipher S-box that enable us to construct
linear approximations of the whole cipher. Using these, it is possible to identify 
the most likely key bits for each round key.
It is a known plaintext attack, requiring that we must have access to 
plaintext/ciphertexts pairs, and the given implementation requires approximately
50 000 such pairs. This is considerably more data than is required by 
the differential attack, but does not require access to an encryption oracle.
