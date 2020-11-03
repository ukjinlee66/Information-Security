#include "global.h"

void construct_key_schedule(char K[], char keys[17][48]){
// generate keys[][] from K[]

   // step 2.1. convert 64-bit K into 56-bit KPlus with 8x7 matrix PC_1
   char KPlus[56];
   permute_8_7(PC_1, K, KPlus);

   // step 2.2. split KPlus into 28-bit C0 and 28-bit D0
   char C[17][28], D[17][28];
   split_KPlus(KPlus, C[0], D[0]);

   // step 2.3. compute Cn, Dn for n=1,2,...16
   comp_Cn_Dn(C, D, ROL);

   // step 2.4. compute Kn by applying PC_2 to CnDn
   comp_keys(C, D, PC_2, keys);
}

void split_KPlus(char KPlus[], char C0[], char D0[]){
// split kplus into c0 and d0
   // ......code........

	int i = 0;
   for(i=0;i<28;i++)
	   C0[i] = KPlus[i];
   for(int j=0;j<28;j++)
	   D0[j] = KPlus[i++];
   printf("after split KPlust\n");
   show_CD(C0, D0);
}
void show_CD(char C[], char D[]){
   for(int i=0;i<28;i++) printf("%d", C[i]);
   printf("\n");
   for(int i=0;i<28;i++) printf("%d", D[i]);
   printf("\n");
}

   
void comp_Cn_Dn(char C[17][28], char D[17][28], int ROL[]){
// compute C1, D1; C2, D2; ... etc using ROL table
   for(int i=1;i<=16;i++){
      comp_Ci_Di(C, D, i, ROL);
      printf("%dth CD\n",i);
      show_CD(C[i], D[i]);
   }
}
void comp_Ci_Di(char C[17][28], char D[17][28], int i, int ROL[]){
// compute C[i], D[i] from C[i-1], D[i-1] using ROL[i]
   // ........... code ...........
   // start index 1
	if (ROL[i] == 1) // shift 1
	{
		int Ctemp = C[i-1][0];
		int Dtemp = D[i-1][0];
		for(int j=1;j<28;j++)
		{
			C[i][j-1] = C[i-1][j];
			D[i][j-1] = D[i-1][j];
		}
		C[i][27] = Ctemp;
		D[i][27] = Dtemp;
	}
	else //shift 2
	{
		int Ctemp1 = C[i-1][0];
		int Ctemp2 = C[i-1][1];
		int Dtemp1 = D[i-1][0];
		int Dtemp2 = D[i-1][1];
		for(int j=2;j<28;j++)
		{
			C[i][j-2] = C[i-1][j];
			D[i][j-2] = D[i-1][j];
		}
		C[i][26] = Ctemp1;
		C[i][27] = Ctemp2;
		D[i][26] = Dtemp1;
		D[i][27] = Dtemp2;
	}
}
void comp_keys(char C[17][28], char D[17][28], int PC_2[8][6], char keys[17][48]){
   char CD[56];
   for(int i=1;i<=16;i++){
      combine_arr(C[i], D[i], CD, 28);
      permute_8_6(PC_2, CD, keys[i]);
   }
   printf("displaying keys\n");
   for(int i=0;i<17;i++){
      printf("K%d=",i);
      show_arr(keys[i], 48);
   }
}

 

       
