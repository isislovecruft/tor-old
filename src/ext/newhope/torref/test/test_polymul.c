#include <stdio.h>
#include "../poly.h"


static void naivemul(poly *r, const poly *x, const poly *y)
{
  uint64_t t[2*PARAM_N];
  uint64_t qmultiple = 2000ULL * PARAM_Q * PARAM_Q;

  int i,j;
  for(i=0;i<2*PARAM_N;i++)
    t[i] = 0;

  for(i=0;i<PARAM_N;i++)
    for(j=0;j<PARAM_N;j++)
      t[i+j] += x->v[i] * y->v[j];

  for(i=0;i<PARAM_N;i++)
    r->v[i] = (t[i] + qmultiple- t[PARAM_N+i]) % PARAM_Q;
}

static void nttmul(poly *r, const poly *x, const poly *y)
{
  poly a,b;
  a = *x;
  b = *y;

  poly_bitrev(&a);
  poly_bitrev(&b);
  poly_ntt(&a);
  poly_ntt(&b);

  poly_pointwise(r,&a,&b);

  poly_bitrev(r);
  poly_invntt(r);
}

int main(void)
{
  poly r,a,b;
  unsigned char pr0[POLY_BYTES];
  unsigned char pr1[POLY_BYTES];
  unsigned char seed[32];
  int i;

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(seed,32,1,urandom);

  poly_uniform(&a, seed);
  seed[0] ^= 1;
  poly_uniform(&b, seed);

  naivemul(&r,&a,&b);
  poly_tobytes(pr0, &r);
  
  nttmul(&r,&a,&b);
  poly_tobytes(pr1, &r);

  for(i=0;i<POLY_BYTES;i++)
    if(pr0[i] ^ pr1[i]) 
      printf("error %d\n", i);

  fclose(urandom);
  return 0;
}
