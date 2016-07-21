#include "../poly.h"
#include "../randombytes.h"
#include "../crypto_stream_chacha20.h"
#include "../error_correction.h"
#include <math.h>
#include <stdio.h>


int compare4(int16_t a[4],int16_t b[4]){
  int i;

  for(i=0; i<4; i++){
    if (a[i] != b[i])
      return -1;
  }

  return 0;
}



int16_t test_rec(){
  //Check that implementation result provides the same values as python implementation in reconciliation.py

  #define TESTS_REC 3

  int i,j;
  int16_t out[4];
  int16_t x[TESTS_REC][4] = {{10408, 599, 5681, 8227},{3224, 12287, 0, 43},{6543, 4234, 8273, 3292}};
  int16_t res0[TESTS_REC][4] = {{1, -2, -1, 5},{1,4,0,0},{1,0,2,6}};
  int16_t res1[TESTS_REC][4] = {{1,  2,  3, 1},{1,0,0,0},{1,0,2,2}};
  int tmp1=0, tmp2=0;
  
  for(j=0; j<TESTS_REC; j++){
    //We test a probablistic function that flips one coin. Both outputs can appear.
    for(i=0; i<20; i++){
      rec(out, x[j]);
      tmp1 = compare4(out,res0[j]);
      tmp2 = compare4(out,res1[j]);
      if(tmp1==-1 && tmp2==-1){
	printf("error\n");
	return -1;
      }
    }
  }

  return 0;
}


int test_key_extraction(){
  #define TESTS_EXTRACT 3
    
  int j;
  int16_t r[TESTS_EXTRACT][4] = {{3,3,0,3},{2, 0, 0, 2},{ 2,  3,  2,  2}};
  int16_t x[TESTS_EXTRACT][4] = {{837, 1660, 4879, 5174}, {3173, 8768, 8492, 8396},{3888, 5780, 3392, 8336}};
  int16_t res0[TESTS_EXTRACT][1] = {{1},{0},{0}};
  
  for(j=0; j<TESTS_EXTRACT; j++){
    if(extract_key_bit(x[j], r[j]) != res0[j][0]){
      printf("error in key extraction, sample %d\n",j);
      return -1;
    }
  }
  
  return 0;
}



int test_decode(){
  #define TESTS_DECODE 3
    
  int j;
  double x[TESTS_DECODE][4] = {{ 6091.625, -6428.875, -5597.875,  6615.875},{ -657.625, -13200.125, 143.125, 1355.625}, {792.75 , 1172.75, -139., 603.75}};
  int16_t res0[TESTS_DECODE][1] = {{0},{1},{1}};
  
  for(j=0; j<TESTS_DECODE; j++){
    if(LLDecode(x[j]) != res0[j][0]){
      printf("error in decode, sample %d\n",j);
      return -1;
    }
  }
  
  return 0;
}



int main(){
  printf("%d\n", test_rec());
  printf("%d\n", test_key_extraction());
  printf("%d\n", test_decode());
 
  return 0;
}
