/*
 *Copyright (C) 2013, Longsheng(lozhou@ucalgary.ca).
 *
 *Use "ShaMan Hash Shared Library (SHA1 SHA256 SHA384 SHA512 MD5 
 *BASE64 + random string generator) Copyright (c) 2007 James 
 *Mrad (xtremejames183@msn.com)" The library is attached in the 
 *submission folder. (http://codes-sources.commentcamarche.net/
 *source/view/43690/1115864)
 *
 *Use the following command to implement the code:
 *$gcc -c singleThread.c md5.c
 *$ar -r libmain.a singleThread.o md5.o
 *$gcc -Wall singleThread.c libmain.a -o singleThread
 *$./singleThread
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include "md5.h"

/*Using the RDTSC instruction to counter CPU tick time.*/
unsigned long int RDTSC (void)
{
  unsigned int low, hi;
  asm volatile ("cpuid \n\t" "rdtsc \n\t": "=a" (low), "=d" (hi) ::);
  return((unsigned long int) hi << 32) | low;
}

/*
 *Single thread that executes sequentially to reverse 
 *the gived hashed digest. Generating the MD5 checksum
 *of all possible messages in the search space. If the
 *chechsum is identical with the given checksum, then
 *the corresponding message is the one we want to find.
 */
int main()
{
  unsigned long int count_begin, count_end;/*CPU Tick Time */
  count_begin=RDTSC();

  MD5_CTX md5;

  /*Given Hashed Version of the Message*/
  unsigned char checksum[16]; 
  checksum[0]=0x57;
  checksum[1]=0x50;
  checksum[2]=0x1a;
  checksum[3]=0xc7;
  checksum[4]=0xb9;
  checksum[5]=0xd5;
  checksum[6]=0x44;
  checksum[7]=0x0a;
  checksum[8]=0xde;
  checksum[9]=0xe8;
  checksum[10]=0xb3;
  checksum[11]=0xdd;
  checksum[12]=0x97;
  checksum[13]=0x09;
  checksum[14]=0x72;
  checksum[15]=0xcb; 	

  int i;
  printf("Hashed Version of the Message is:\n");
  for(i=0;i<16;i++)
  {
    printf("%02x",checksum[i]);	
  }
  printf("\n");

  unsigned char characters[63];  /*Search Space*/
  characters[0]=0x30; /* "0" */
  characters[1]=0x31;
  characters[2]=0x32;
  characters[3]=0x33;
  characters[4]=0x34;
  characters[5]=0x35;
  characters[6]=0x36;
  characters[7]=0x37;
  characters[8]=0x38;
  characters[9]=0x39; /* "9" */
  characters[10]=0x41;/* "A" */
  characters[11]=0x42;
  characters[12]=0x43;
  characters[13]=0x44;
  characters[14]=0x45;
  characters[15]=0x46;
  characters[16]=0x47;
  characters[17]=0x48;
  characters[18]=0x49;
  characters[19]=0x4a;
  characters[20]=0x4b;
  characters[21]=0x4c;
  characters[22]=0x4d;
  characters[23]=0x4e;
  characters[24]=0x4f;
  characters[25]=0x50;
  characters[26]=0x51;
  characters[27]=0x52;
  characters[28]=0x53;
  characters[29]=0x54;
  characters[30]=0x55;
  characters[31]=0x56;
  characters[32]=0x57;
  characters[33]=0x58;
  characters[34]=0x59;
  characters[35]=0x5a;/* "Z" */
  characters[36]=0x61;/* "a" */
  characters[37]=0x62;
  characters[38]=0x63;
  characters[39]=0x64;
  characters[40]=0x65;
  characters[41]=0x66;
  characters[42]=0x67;
  characters[43]=0x68;
  characters[44]=0x69;
  characters[45]=0x6a;
  characters[46]=0x6b;
  characters[47]=0x6c;
  characters[48]=0x6d;
  characters[49]=0x6e;
  characters[50]=0x6f;
  characters[51]=0x70;
  characters[52]=0x71;
  characters[53]=0x72;
  characters[54]=0x73;
  characters[55]=0x74;
  characters[56]=0x75;
  characters[57]=0x76;
  characters[58]=0x77;
  characters[59]=0x78;
  characters[60]=0x79;
  characters[61]=0x7a;/* "z"  */
  characters[62]=0x20;/* "SPACE" character*/

  unsigned char message[11];/*Message has 11 characters*/
  unsigned char hashed[16];/*Hashed version of the above message[11]*/

  int a, b, c, d, e, f;
  int FLAG=0;
  
  /*Signal handler that catches SIGUSR2, reporting how far through the search space
   *it has progressed.*/
  void sig_usr(int signo)
  {
    if(signo == SIGUSR2){
      printf("Received SIGUSR2\n");
      printf("Program has just checked message:\n");
      printf("character[0]=%c\ncharacter[1]=%c\ncharacter[2]=%c\n",characters[a],characters[b],characters[c]);
      printf("character[3]=%c\ncharacter[4]=%c\ncharacter[5]=%c\n",characters[62],characters[44],characters[d]);
      printf("character[6]=%c\ncharacter[7]=%c\ncharacter[8]=%c\n",characters[62],characters[e],characters[50]);
      printf("character[9]=%c\ncharacter[10]=%c\n",characters[f],characters[47]);
    }
  }

  /*Search Space Traversal*/
  for(a=0;a<63;a++){
    for(b=0;b<63;b++){
      for(c=0;c<63;c++){
	for(d=0;d<63;d++){
	  for(e=0;e<63;e++){
	    for(f=0;f<63;f++){
	      
	      message[0]=characters[a];
	      message[1]=characters[b];
	      message[2]=characters[c];
	      message[3]=0x20;
	      message[4]=0x69;	 
	      message[5]=characters[d];
	      message[6]=0x20;
	      message[7]=characters[e];
	      message[8]=0x6f;
	      message[9]=characters[f];
	      message[10]=0x6c;	
	     
	      /*MD5 initialization. Begins an MD5 operation, writing a new context(md5).*/
	      MD5Init(&md5);
	      
	      /*MD5 block update operation. Continues an MD5 message-digest operation, processing 
	       *another message block,and updating the context(md5).*/
	      MD5Update(&md5,message,strlen((char *)message)); 
	      
	      /*MD5 finalization. Ends an MD5 message-digest operation, writing the
	       *the message digest and zeroizing the context(md5).*/
	      MD5Final(&md5,hashed);
	      
	      int k;
	      int t=0;
	      for(k=0;k<16;k++){
		if(hashed[k]==checksum[k]){
		  t++;
		}
	      }

	      if(signal(SIGUSR2, sig_usr) == SIG_ERR)
		printf("can't catch SIGUSR2\n");
      
	      if(t==16){
		FLAG=1;/*I find the message!*/
		printf("Original Message is: ");
		int j;
		for(j=0;j<11;j++){
		  printf("%c", message[j]);
		}	
		printf("\n");
	      }
	      if(FLAG==1)
		break;
	    }
	    if(FLAG==1)
	      break;
	  }
	  if(FLAG==1)
	    break;
	}
	if(FLAG==1)
	  break;
      }
      if(FLAG==1)
	break;
    }
    if(FLAG==1)
      break;
  }
  
  if(FLAG==0)
      printf("Oops, Message is not found!\n");

  count_end = RDTSC();
  printf("CPU Tick Time: %lu\n", count_end-count_begin);
  
  return 0;
}
