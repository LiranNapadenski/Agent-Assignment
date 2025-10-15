# Agent-Assignment

in order to compile run : make

to start the test run : make run-tests
(might take some time beacuse some of the test cases includes 20 gb files )

to delete the compiled files run : make clean

to run the program - ./find_sig path_of_root path_of_sig


**Changes from first submission**

In the first submition i loaded all of the file to a vector in memory then run a built in pattern search algorithm this caused errors for large files as there wasnt enough memmory

I first tried fixing the problame of memmory by using deque instead of vector - I read a byte at a time adding it to the deque and deleting the oldest byte then doing a comparison to the signiture. this method did work but was very slow.

The current method i use is loading the file by constant size chuncks to an in memmory vector and running on the chunck the built-in search algorithm - after loading  the chunck I go a bit back in the file to ensure that if the malicous signiture is between the chunks (overlaps between the chuncks) I will still manage to locate it

***tests***

I added some integration test including - 
scan on large files (20gb),
files that are not ELF but contain the signiture


I hope you will find it to your requests ,
Liran Napadenski
