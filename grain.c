//please check the comments for updated changes
//comments on line 42 &43
//again from line 79

#include<stdio.h>
#include<string.h>

#define INITCLOCKS 160
#define N(i) (mygrain->NFSR[80-i])
#define L(i) (mygrain->LFSR[80-i])
#define X0 (mygrain->LFSR[3])
#define X1 (mygrain->LFSR[25])
#define X2 (mygrain->LFSR[46])
#define X3 (mygrain->LFSR[64])
#define X4 (mygrain->NFSR[63])
 
typedef struct
{
	int LFSR[80];
	int NFSR[80];
	const int* p_key;
	int keysize;
	int ivsize;
 
} grain;



int grain_keystream(grain* mygrain){
    //function for updating the LFSR and NFSR
    int j,newNFSRbit,newLFSRbit,outputBit;

    //outputbit calculation

    outputBit = N(79)^N(78)^N(76)^N(70)^N(49)^N(37)^N(24) ^ X1 ^ X4 ^ X0&X3 ^ X2&X3 ^ X3&X4 ^ X0&X1&X2 ^ X0&X2&X3 ^ X0&X2&X4 ^ X1&X2&X4 ^ X2&X3&X4;

    newNFSRbit = L(80)^N(18)^N(20)^N(28)^N(35)^N(43)^N(47)^N(52)^N(59)^N(66)^N(71)^N(80)^
			N(17)&N(20) ^ N(43)&N(47) ^ N(65)&N(71) ^ N(20)&N(28)&N(35) ^ N(47)&N(52)&N(59) ^ N(17)&N(35)&N(52)&N(71)^
			N(20)&N(28)&N(43)&N(47) ^ N(17)&N(20)&N(59)&N(65) ^ N(17)&N(20)&N(28)&N(35)&N(43) ^ N(47)&N(52)&N(59)&N(65)&N(71)^
			N(28)&N(35)&N(43)&N(47)&N(52)&N(59);

    newLFSRbit = L(18)^L(29)^L(42)^L(57)^L(67)^L(80);

    for (j=2;j<(mygrain->keysize)-1;++j) {//this is the update function for LFSR and NFSR
		mygrain->NFSR[j-2]=mygrain->NFSR[j];//instead of shifting the bits one at a time 2 are shifted at a time
		mygrain->NFSR[j-1]=mygrain->NFSR[j+1];
		mygrain->LFSR[j-2]=mygrain->LFSR[j];
		mygrain->LFSR[j-1]=mygrain->LFSR[j+1];
	}
 
    mygrain->NFSR[(mygrain->keysize)-1]=newNFSRbit;
	mygrain->NFSR[(mygrain->keysize)-2]=newNFSRbit;
	mygrain->LFSR[(mygrain->keysize)-2]=newLFSRbit;
	mygrain->LFSR[(mygrain->keysize)-1]=newLFSRbit;

    
    return outputBit;

}

void keysetup(grain* mygrain,const int* key,int keysize,int ivsize){
    mygrain->p_key = key;
    mygrain->keysize = keysize;
    mygrain->ivsize = ivsize;
}

void ivsetup(grain* mygrain,const int* iv){
    int i,j;
    int outputBit;

    for(i=0;i<(mygrain->ivsize)/8;++i){
        for(j=0;j<8;++j){
            mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);  
            mygrain->LFSR[i*8+j]=((iv[i]>>j)&1);
        }
    }
	

	int counter=0,xor=0,pointer=0,xorArray[16];//the part of the code here instead of filling all ones in the lfsr last 16bits
	 for(i=0;i<(mygrain->keysize)/8;++i){//this function takes care that the last bits of the lfsr are filled in the following way
        for(j=0;j<8;++j){                               //calculate the bitwise xor for every 5 bits in the key
		                                                //then you will get 16 such bits (80bits in key/5)      
            if(counter!=0 && counter%5==0){
				                                    //fill the last 16 bits such that every bit is equal to not of the value of the above 
													//obtained 16 bits
				xorArray[pointer++] = !xor;   //xorArray  calculates the required bits;
				xor = 0;
			}
			xor = xor ^ ((mygrain->p_key[i]>>j)&1);
			counter++;
        }
    }
	xorArray[pointer++]=xor;
    for (i=(mygrain->ivsize)/8;i<(mygrain->keysize)/8;++i) {
		for (j=0;j<8;++j) {
			mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);
		}
	}
    for(i=64;i<80;i++){
		mygrain->LFSR[i]=xorArray[i-64];   //filling the required bits in the LFSR from xorArray
	}
	
    for (i=0;i<INITCLOCKS;++i) {
		outputBit=grain_keystream(mygrain);
        
		mygrain->LFSR[79]^=outputBit;
		mygrain->NFSR[79]^=outputBit;             
	}
}

void keystream_bytes(grain* mygrain,int* keystream,int msglen){
    int i,j;
    for(i=0;i<msglen;i++){
        keystream[i]=0;
        for(j=0;j<8;j++){
            int x;
            x=(grain_keystream(mygrain)<<j);
            keystream[i]|=(x);
        }
    }
}

void encrypt_bytes(grain* mygrain,const int* plaintext,int* ciphertext,int msglen){
    	int i,j,k;
	for(i = 0; i < msglen;i++) {
		k=0;
		for (j = 0; j < 8;j++) {	
			k|=(grain_keystream(mygrain)<<j);
		}
		ciphertext[i]=plaintext[i]^k;
	}
}
void decrypt_bytes(grain* mygrain,const int* ciphertext,int* plaintext,int msglen){
    int i,j,k;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {
			k|=(grain_keystream(mygrain)<<j);
		}
		plaintext[i]=ciphertext[i]^k;
	}
}

void outputData(int *key, int *IV, int *ks, int *pt, int *et, int *dt, int sizeOfPlaintext){
    	int i;
	printf("key:        ");
	for (i=0;i<10;++i) printf("%02x",(int)key[i]);
	printf("\nIV :        ");
	for (i=0;i<8;++i) printf("%02x",(int)IV[i]);
	printf("\nkeystream:  ");
	for (i=0;i<10;++i) printf("%02x",(int)ks[i]);
	printf("\nplaintext:  ");
	for (i=0;i<sizeOfPlaintext;i++) printf("%02x",(int)pt[i]);
	printf("\nencrypted text:  ");
	for (i=0;i<sizeOfPlaintext;i++) printf("%02x",(int)et[i]);
	printf("\ndecrypted text:  ");
	for (i=0;i<sizeOfPlaintext;i++) printf("%02x",(int)dt[i]);
}
int main(int argc,char **argv){
    int plaintext[10]={0x99,0x63,0x11,0x55,0x00,0x99,0x63,0x11,0x55,0x00};
	int sizeOfPlaintext=10; //fill size here
	int encrypted_text[10];
	int decrypted_text[10];
 
	grain mygrain;
		int key1[10] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		IV1[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	    ks[10];
 
	int key2[10] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x12,0x34},
		IV2[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
 
 
 
	printf("\nTestCase: 1\n");
	keysetup(&mygrain,key1,80,64);
	ivsetup(&mygrain,IV1);
	keystream_bytes(&mygrain,ks,10);
	grain mygrain2 = mygrain;
	encrypt_bytes(&mygrain,plaintext,encrypted_text,10);
	decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,10);
	outputData(key1,IV1,ks, plaintext, encrypted_text, decrypted_text, 10);
 
 
	printf("\n\nTestCase: 2\n");
	keysetup(&mygrain,key2,80,64);
	ivsetup(&mygrain,IV2);
	keystream_bytes(&mygrain,ks,10);
	mygrain2 = mygrain;
	encrypt_bytes(&mygrain,plaintext,encrypted_text,10);
	decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,10);
	outputData(key2,IV2,ks, plaintext, encrypted_text, decrypted_text, 10);
 
	
 
	return 0;

}

