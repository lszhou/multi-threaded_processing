/*
 *Copyright (C) 2013, Longsheng(lozhou@ucalgary.ca).
 *
 *Use "ShaMan Hash Shared Library (SHA1 SHA256 SHA384 SHA512 MD5 
 *BASE64 + random string generator) Copyright (c) 2007 James 
 *Mrad (xtremejames183@msn.com)" The library is attached in the 
 *submission folder. (http://codes-sources.commentcamarche.net/
 *source/view/43690/1115864)
 *
 *syscall clone(2) based program that splits up the search space and 
 *recover the hased concurrently.
 *
 *command line:
 *[lozhou@ict609e] gcc -c nprocess.c md5.c
 *[lozhou@ict609e] ar -r libmain.a nprocess.o md5.o
 *[lozhou@ict609e] gcc -Wall nprocess.c libmain.a -o nprocess
 *[lozhou@ict609e] ./nprocess
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <linux/sched.h>   
#include <malloc.h>
#include <sys/wait.h>
#include <syscall.h>
#include "md5.h"

#define FIBER_STACK 1024*64 /*64KB*/

void *stack1, *stack2, *stack3, *stack4;
static int FLAG=0;

int process1()
{
  printf("Process 1 is created, PID=%d\n", getpid());
  
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

   /*Search Space*/
  unsigned char characters[63];
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
  MD5_CTX md5;

  int a1, a2, a3, a4, a5, a6;
  for(a1=4;a1<31;a1++){
    for(a2=3;a2<63;a2++){
      for(a3=0;a3<63;a3++){
	for(a4=0;a4<63;a4++){
	  for(a5=0;a5<63;a5++){
	    for(a6=0;a6<63;a6++){
	      message[0]=characters[a1];
	      message[1]=characters[a2];
	      message[2]=characters[a3];
	      message[3]=0x20;
	      message[4]=0x69;			 
	      message[5]=characters[a4];
	      message[6]=0x20;
	      message[7]=characters[a5];
	      message[8]=0x6f;
	      message[9]=characters[a6];
	      message[10]=0x6c;	
	      
	      /*MD5 initialization. Begins an MD5 operation, writing a new context(md5)*/
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
	      
	      if(t==16){
		FLAG=1;
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
      printf("Process 1 has reached a1=%u a2=%u\n", a1, a2);/*Show the progress.*/
      if(FLAG==1)
	break;
    }
    if(FLAG==1)
      break;
  }
  
  if(FLAG==0){
    printf("Oops, process 1 didn't find the message.\n");
  }
  
  free(stack1);
  exit(1);
  return 0;
}


int process2()
{
  printf("Process 2 is created, PID=%d\n", getpid());

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

  unsigned char characters[63];
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

  unsigned char message[11];
  unsigned char hashed[16];
  MD5_CTX md5;

  int b1, b2, b3, b4, b5, b6;
  for(b1=31;b1<63;b1++){
    for(b2=0;b2<63;b2++){
      for(b3=0;b3<63;b3++){
	for(b4=0;b4<63;b4++){
	  for(b5=0;b5<63;b5++){
	    for(b6=0;b6<63;b6++){
	      message[0]=characters[b1];
	      message[1]=characters[b2];
	      message[2]=characters[b3];
	      message[3]=0x20;
	      message[4]=0x69;			 
	      message[5]=characters[b4];
	      message[6]=0x20;
	      message[7]=characters[b5];
	      message[8]=0x6f;
	      message[9]=characters[b6];
	      message[10]=0x6c;	
	      
	      MD5Init(&md5);
	      MD5Update(&md5,message,strlen((char *)message));
	      MD5Final(&md5,hashed);

	      int k;
	      int t=0;
	      for(k=0;k<16;k++){
		if(hashed[k]==checksum[k]) {
		  t++;
		}
	      }	
	      
	      if(t==16){
		FLAG=1;
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
      printf("Process 2 has reached b1=%u b2=%u\n", b1, b2);
      if(FLAG==1)
	break;
    }
    if(FLAG==1)
      break;
  }
 
  if(FLAG==0){
    printf("Oops, process 2 didn't find the message.\n");
  }

  free(stack2);
  exit(1); 
  return 0;
}


int process3()
{
  printf("Process 3 is created, PID=%d\n", getpid());
  
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

  unsigned char characters[63];
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
  MD5_CTX md5;

  int c1, c2, c3, c4, c5, c6;
  for(c1=33;c1<49;c1++){
    for(c2=0;c2<63;c2++){
      for(c3=0;c3<63;c3++){
	for(c4=0;c4<63;c4++){
	  for(c5=0;c5<63;c5++){
	    for(c6=0;c6<63;c6++){
	      message[0]=characters[c1];
	      message[1]=characters[c2];
	      message[2]=characters[c3];
	      message[3]=0x20;
	      message[4]=0x69;			 
	      message[5]=characters[c4];
	      message[6]=0x20;
	      message[7]=characters[c5];
	      message[8]=0x6f;
	      message[9]=characters[c6];
	      message[10]=0x6c;	
	      
	      MD5Init(&md5);
	      MD5Update(&md5,message,strlen((char *)message));
	      MD5Final(&md5,hashed);
	      
	      int k;
	      int t=0;
	      for(k=0;k<16;k++){
		if(hashed[k]==checksum[k]){
		  t++;
		}
	      }	
	      
	      if(t==16){
		FLAG=1;
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
      printf("Process 3 has reached c1=%u c2=%u\n", c1, c2);/*Show the progress.*/
      if(FLAG==1)
	break;
    }
    if(FLAG==1)
      break;
  }
  
  if(FLAG==0){
    printf("Oops, process 3 didn't find the message.\n");
  }
  
  free(stack3);
  exit(1);
  return 0;
}

int process4()
{
  printf("Process 4 is created, PID=%d\n", getpid());
  
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

  unsigned char characters[63];
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
  MD5_CTX md5;

  int d1, d2, d3, d4, d5, d6;
  for(d1=49;d1<63;d1++){
    for(d2=0;d2<63;d2++){
      for(d3=0;d3<63;d3++){
	for(d4=0;d4<63;d4++){
	  for(d5=0;d5<63;d5++){
	    for(d6=0;d6<63;d6++){
	      message[0]=characters[d1];
	      message[1]=characters[d2];
	      message[2]=characters[d3];
	      message[3]=0x20;
	      message[4]=0x69;			 
	      message[5]=characters[d4];
	      message[6]=0x20;
	      message[7]=characters[d5];
	      message[8]=0x6f;
	      message[9]=characters[d6];
	      message[10]=0x6c;	
	      
	      MD5Init(&md5);
	      MD5Update(&md5,message,strlen((char *)message));
	      MD5Final(&md5,hashed);
	      
	      int k;
	      int t=0;
	      for(k=0;k<16;k++){
		if(hashed[k]==checksum[k]){
		  t++;
		}
	      }	
	      
	      if(t==16){
		FLAG=1;
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
      printf("Process 4 has reached d1=%u d2=%u\n", d1, d2);/*Show the progress.*/
      if(FLAG==1)
	break;
    }
    if(FLAG==1)
      break;
  }
  
  if(FLAG==0){
    printf("Oops, process 4 didn't find the message.\n");
  }
  
  free(stack4);
  exit(1);
  return 0;
}


/*Using the RDTSC instruction to counter CPU tick time.*/
unsigned long int RDTSC (void)
{
  unsigned low, hi;
  unsigned long long val;
  asm volatile ("cpuid \n\t" "rdtsc \n\t": "=a" (low), "=d" (hi) ::);
  val=hi;
  val=(val << 32) | low;
  return val;
}

int main(void)
{
  unsigned long int count_begin, count_end;

  count_begin=RDTSC();
  printf("Program Timing Start!\n");
  
  stack1=malloc(FIBER_STACK);
  stack2=malloc(FIBER_STACK);
  stack3=malloc(FIBER_STACK);
  stack4=malloc(FIBER_STACK);
 
  if(!stack1){
    printf("Application for stack1 failed\n");
    exit(0);
  }
  if(!stack2){
    printf("Application for stack2 failed\n");
    exit(0);
  }
  if(!stack3){
    printf("Application for stack3 failed\n");
    exit(0);
  }
  if(!stack4){
    printf("Application for stack4 failed\n");
    exit(0);
  }
  
  printf("Trying to creat threads......\n");
  clone(&process1, (void *)stack1 + FIBER_STACK, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, NULL);
  clone(&process2, (void *)stack2 + FIBER_STACK, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, NULL);
  clone(&process3, (void *)stack3 + FIBER_STACK, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, NULL);
  clone(&process4, (void *)stack4 + FIBER_STACK, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, NULL);
  
  
  int status1, status2, status3, status4; 
  while(wait(&status1)<=0){
    //wait;
  }
  while(wait(&status2)<=0){
    //wait;
  }
  while(wait(&status3)<=0){
    //wait;
  }
  while(wait(&status4)<=0){
    //wait;
  }

  printf("All processes are done!\n");
  printf("Timing End!\n");
  count_end = RDTSC();
 
  printf("CPU Tick Time: %lu\n", count_end-count_begin);
  
  return 0;
}
