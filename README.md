# PyGTFO
GTFOBins Offline Terminal with python

**A python3 script which uses a custom GTFOBins dictionary to search and report how to exploit all the possible binaries ^^**

<img src="https://i.imgur.com/ifdb7oO.png" />

### Description
A script made in python3 to perferm offline an offline seach in GTFOBins to use in machines/CTFs and do the following
- List all the binaries in the disctionary
- List all the privileges available for each binary
- Print how to exploit a specific binary by privileges

### Notes

The dictionary is not complete in this moment, I will be updating it in the following days.

### Download & Use

	wget [] --no-check-certificate && chmod 777 suid3num.py
	
### Usage

***Initializing Script***

	python3 pyGTFO.py -b [BINARY] -p [PRIVILEGE]
	
***List all binaries and privileges***

	python3 pyGTFO.py -lb (List all binaries)
	python3 pyGTFO.py -b [BINARY] -lp (List all possible privileges)

***Show usage menu***

	python3 pyGTFO.py -m

### Output

<img src="https://i.imgur.com/xU4Djpm.png" />

<img src="https://i.imgur.com/uB9Y3pn.png" />

<img src="https://i.imgur.com/wHzdex9.png" />

Let me know what you think of this script at [@DrakuKled](https://twitter.com/DrakuKled) 
