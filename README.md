# PyGTFO
GTFOBins Offline Terminal with python

**A python3 script which uses a custom GTFOBins dictionary to search and report how to exploit all the possible binaries ^^**

<img src="https://i.imgur.com/ifdb7oO.png" />

### Description
A script made in python3 to perferm an offline seach in GTFOBins to use in machines and do the following:
- List all the binaries in the disctionary
- List all the privileges available for each binary
- Print how to exploit a specific binary by privileges

### Notes

Some unusual commands are missing, i will be updating it in the future.

### Dependencies

PyGTFO requires the following non-standard Python libraries to be installed:

	colorama (pip install colorama)
	
It can also be installed with the command: pip install -r requirements.txt

### Download & Use

	git clone https://github.com/WizzzStark/PyGTFO 
	
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

Let me know what you think of this script at [@DrakuKled](https://twitter.com/WizzzStark) 
