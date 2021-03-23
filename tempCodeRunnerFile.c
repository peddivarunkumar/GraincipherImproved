void keysetup(grain* mygrain,const int* key,int keysize,int ivsize);
void ivsetup(grain* mygrain,const int* iv);
void keystream_bytes(grain* mygrain,int* keystream,int length);
void encrypt_bytes(grain* mygrain,const int* plaintext,int* ciphertext,int msglen);
void decrypt_bytes(grain* mygrain,const int* ciphertext,int* plaintext,int msglen);
int grain_keystream(grain* mygrain);