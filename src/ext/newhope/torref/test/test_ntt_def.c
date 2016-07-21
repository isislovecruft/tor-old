#include "../newhope.h"
#include "../poly.h"
#include "../randombytes.h"
#include "../crypto_stream_chacha20.h"
#include "../error_correction.h"
#include "../error_correction.h"
#include "../fips202.h"
#include "../ntt.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define NTESTS 10


static uint16_t get_power(uint16_t x, uint16_t power);

static uint16_t get_power(uint16_t x, uint16_t power){
  uint16_t i;
  uint16_t val;

  val = 1;
  for(i=0; i<power; i++){
    val = (((uint32_t)val)*x) % PARAM_Q;
  }

  return val;
}


/* Super naive implementation of the NTT + psi mul - to check definition of encoding */
void naive_transform(uint16_t * a, uint16_t psi)
{
  uint16_t i,j;
  uint16_t temp[PARAM_N];
  uint16_t omega;

  omega = (((uint32_t)psi) * psi) % PARAM_Q;

  for(i=0; i<PARAM_N; i++)
    temp[i] = ((uint32_t)a[i] * get_power(psi, i))%PARAM_Q;

  for(i=0;i<PARAM_N; i++)
  {
    a[i]=0;
    for(j=0; j<PARAM_N; j++)
    {
      a[i] += ((uint32_t)temp[j] * get_power(omega, (i*j) % PARAM_N)) % PARAM_Q;
      a[i] %= PARAM_Q;
    }
  }
}

/* Super naive implementation of the NTT + psi mul - to check definition of encoding */
void naive_inverse(uint16_t * a)
{
  uint16_t i,j;
  uint16_t temp[PARAM_N];
  uint16_t invpsi 8778;
  uint16_t invomega = 1254;
  uint16_t invn 12277;

  for(i=0; i<PARAM_N; i++)
    temp[i] = a[i]

  for(i=0;i<PARAM_N; i++)
  {
    a[i]=0;
    for(j=0; j<PARAM_N; j++)
    {
      a[i] += ((uint32_t)temp[j] * get_power(invomega, (i*j) % PARAM_N)) % PARAM_Q;
      a[i] %= PARAM_Q;
    }
  }

  for(i=0; i<PARAM_N; i++)
  {
    a[i] = ((uint32_t)a[i] * get_power(invpsi, i))%PARAM_Q;
    a[i] = ((uint32_t)a[i] * get_power(invn, i))%PARAM_Q;
  }
}



int main(void)
{

  //This function uses the high speed NTT and a naive defintion and compares the result
  unsigned char seed[32];

  uint16_t i,j;
  uint16_t b[PARAM_N];
  poly a;


  for(j=0; j<NTESTS; j++){
    randombytes(seed, 32);

    poly_uniform(&a, seed); //unsigned

    for(i=0; i<PARAM_N; i++){
      b[i] = a.v[i];
    }

    bitrev_vector(a.v);
    poly_ntt(&a); 

    naive_transform(b, 7);

    for(i=0; i<PARAM_N; i++)
    {
      a.v[i] = a.v[i] % PARAM_Q;
      if (a.v[i] != b[i])
      {
        printf("%u",i);
        printf("(%u, %u)\n", a.v[i], b[i]);
        return -1;
      }
    }

    printf("all good\n");

  }

  return 0;
}
