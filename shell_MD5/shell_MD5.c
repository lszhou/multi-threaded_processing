#include<time.h>
#include<stdlib.h>
#include<stdio.h>

/*Using the RDTSC instruction to counter CPU tick time.*/
/*
unsigned long int RDTSC (void){
  unsigned long int low, hi; 
  asm volatile ("cpuid \n\t" "rdtsc \n\t": "=a" (low), "=d" (hi) ::); 
  return((unsigned long int) hi << 32) | low;
}
*/

unsigned long int RDTSC (void)
{
  unsigned low, hi;
  unsigned long long val;
  asm volatile ("cpuid \n\t" "rdtsc \n\t": "=a" (low), "=d" (hi) ::);
  val=hi;
  val=(val << 32) | low;
  return val;
}

int main()
{
  unsigned long int count_begin, count_end;
  double mhz=2542.502;/*CPU MHz from /proc/cpuinfo file*/

  count_begin=RDTSC(); 

  system ("echo -n aaaaaaaaaaa| md5sum");/*test message*/
  //sleep(1);

  count_end=RDTSC();
  
  printf("CUP tick time: %lu\n", count_end-count_begin);
  printf("Running Time: %g usec\n", (count_end-count_begin)/mhz); 

  return 0;
}
