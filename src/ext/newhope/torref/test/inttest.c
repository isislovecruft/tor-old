#include <stdio.h>
#include "../error_correction.h"
#include "../randombytes.h"

#define NTESTS 1000000
//#define NTESTS 100

int main()
{
  int i;
  double temp[4];
  int32_t tempi[4];
  unsigned char bits[1]; 
  int16_t resd[4], resi[4], x[4];
  unsigned long long n;


  for(n=0;n<NTESTS;n++)
  {
    randombytes((unsigned char *)x,8);
    for(i=0;i<4;i++)
      x[i] &= 0x3fff; // Inputs have only 14 bits.

    randombytes(bits,1);
    bits[0] = bits[0] %2;

    for(i=0; i<4; i++){
      temp[i] = 4.0*((double) x[i] *(1.0)/PARAM_Q + bits[0]*0.5); 
      tempi[i] = 8*x[i] + 4*PARAM_Q*bits[0]; 
    }

    CVPD4(resd, temp);
    //CVPD4_int(resi, tempi);
    CVPD4_int(resi, tempi[0], tempi[1], tempi[2], tempi[3]);

    for(i=0;i<4;i++) 
      if(resi[i] != resd[i]) printf("-1\n");
  }

  return 0;
}
