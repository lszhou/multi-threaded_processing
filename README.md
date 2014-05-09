Multithreads
============

Multithreads programming in C


Recovered the messsage from the given hashed digest
- single thread
- pthread
- clone(2)-based

Src description:

Single thread

-shell_MD5.c      /*enchmarking md5sum(1) in a loop to get good estimate*/

pthread-based program:

-singleThread.c   /*sing thread program source code*/

-md5.h            /*ShaMan Hash Shared Library md5 head file*/

-md5.c            /*ShaMan Hash Shared Library md5 source code*/

-2threads.c       /*2 threads program*/

-nthreads.c       /*n threads program, n=4*/

clone(2)-based program

-2process.c       /*clone-based 2 processes program*/

-nprocess.c       /*clone-based 4 processes program*/

"ShaMan Hash Shared Library"(Copyright (c) 2007James Mrad).tar.gz
/*shared library that provides md5 algorithm*/


Technical Details:
A.a) Using system(3) to execute shell command "echo -n ss| md5sum". 
     and use RDTSC() to calculate the CPU tick time; checking the /proc/cpuinfo
     file to read the CPU MHz=2542.502, than calculating the required time, 
     namely how long it takes to compute a single md5 digest.

     [lozhou@ict~]$gcc shell_MD5.c -o shell_MD5
     [lozhou@ict~]$./shell_MD5
     Running Time: 2651.34 usec

     So it takes 5179.57 usec to compute an md5 digest.
     Because the each character choosing from a,...,z,A,...Z,0,...,9 and "space".
     If gussing the missing 6 characters, it will take (63^6)x2651.34 usec 
     If gussing the missing 8 characters, it will take (63^8)x2651.34 usec
     If gussing the missing 11 characters, it will take (63^11)x2651.34 usec
     
     It is a very very long time to do so in such a huge search space.
     

A) In the singleThread.c, I use "ShaMan Hash Shared Library" (SHA1 SHA256 SHA384
   SHA512 MD5 BASE64 + random string generator) Copyright (c) 2007 James Mrad 
   (xtremejames183@msn.com)". The library is attached in the submission folder. 
   (http://codes-sources.commentcamarche.net/source/view/43690/1115864). 
   (Although Dr.Locasto provides the library gcrypt, but he said we could feel 
   free to use the other library. The "ShaMan Hash Shared Library" provide many
   hased algorithms, for simplification and for your making convenivence, I as 
   well pick the md5 related files to do the homework, namely "md5.c" and 
   "md5.h".(You can also install the labrary.)   
 
   Using the following style to execute the program.
   [lozhou@ict~]$gcc -c singleThread.c md5.c
   [lozhou@ict~]$ar -r libmain.a singleThread.o md5.o
   [lozhou@ict~]$gcc -Wall singleThread.c libmain.a -o singleThread
   [lozhou@ict~]$./singleThread

   I added a single handler to the singleThread program to report how far through 
   the search space it has progressed. Using the following command to get the 
   progress report:

   [lozhou@ict609e~]$./singleThread &
   [1] 5109
   [lozhou@ict609e~]$kill -USR2 5109
   Received SIGUSR2
   Program has just checked message:
   character[0]=0
   character[1]=2
   character[2]=t
   character[3]=     /*means "space" character*/
   character[4]=i
   character[5]=r
   character[6]= 
   character[7]=B
   character[8]=o
   character[9]=Q
   character[10]=l

   singleThread program applied RDTSC() to report the program running time, and
   through checking /proc/cpuinfo to get the VM and CPSC machine CPU MHz values.
              
   Further details about the c source code please refer to the comments in the 
   singleThread.c.

B) I wrote a 2-threaded program (2threads.c) and 4-threaded program. They split
   up the search space into 2 and 4 respectively. I picked the order that the 
   characters are represented in the ASCII table.

   I use pthread_create() to creat multi-processes and use RDTSC() to report 
   the CPU tick time.

   You can use the following commands to execute the 2threads.c, nthreads.c 
   is just the same:
   [lozhou@ict~]$gcc -c -pthread 2threads.c md5.c
   [lozhou@ict~]$ar -r libmain.a 2threads.o md5.o
   [lozhou@ict~]$gcc -Wall -pthread 2threads.c libmain.a -o 2threads
   [lozhou@ict~]$./2threads
   
   Further details about the c source code please refer to the comments in the 
   2threads.c and nthreads.c.

C) I wrote a 2-process program (2process.c) and 4-process program (4process.c). 
   They split up the search space into 2 and 4 respectively. I picked the order
   that the characters are represented in the ASCII table.

   I use malloc(3) to allocate dynamic memory; use RDTSC() to report the 
   CPU tick time; use clone(2) to creates multi-processes; use wait(2) to wait 
   for process to change for state.

   You can use the following commands to execute the 2threads.c, nthreads.c 
   is just the same:

   [lozhou@ict~]$gcc -c -pthread 2threads.c md5.c
   [lozhou@ict~]$ar -r libmain.a 2threads.o md5.o
   [lozhou@ict~]$gcc -Wall -pthread 2threads.c libmain.a -o 2threads
   [lozhou@ict~]$./2threads
   
   Further details about the c source code please refer to the comments in 
   the 2process.c and nprocess.c.
