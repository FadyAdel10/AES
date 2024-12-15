#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
/*
                 Name                 ID
        ------------------------------------
        | Fady Adel Botros       | 2001388 |
        | Ahmed Ayman AbdElFatah | 2000128 |
        | Ahmed Mohamed Atwa     | 2001391 |
        | Ahmed Sherif Mohamed   | 2001547 |
        | Omar Nader Ahmed Gamal | 2001714 |
        ------------------------------------
*/






const uint8_t AES_Sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
const uint8_t AES_InvSbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

uint32_t te0[256], te1[256], te2[256], te3[256];

uint32_t td0[256], td1[256], td2[256], td3[256];

uint8_t xtime(uint8_t X)
    {
        return (X << 1) ^ ((X & 0x80) ? 0x1B : 0x00);
    }
// compute AES 32-bit encryption tables
void compute_encTables(uint32_t T0[256], uint32_t T1[256], uint32_t T2[256], uint32_t T3[256])
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint8_t x = AES_Sbox[i];
        uint8_t x2 = xtime(x);
        uint8_t x3 = x2 ^ x;

        T0[i] = (x2 << 24) | (x << 16) | (x << 8) | x3;
        T1[i] = (x3 << 24) | (x2 << 16) | (x << 8) | x;
        T2[i] = (x << 24) | (x3 << 16) | (x2 << 8) | x;
        T3[i] = (x << 24) | (x << 16) | (x3 << 8) | x2;
    }
}

// compute AES 32-bit deccryption tables
void compute_decTables(uint32_t T0[256], uint32_t T1[256], uint32_t T2[256], uint32_t T3[256])
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint8_t x = AES_InvSbox[i];
        uint8_t xE = xtime(xtime(xtime(x)) ^ xtime(x) ^ x); // Multiply x by 0x0E
        uint8_t xB = xtime(xtime(xtime(x)) ^ x) ^ x;        // Multiply x by 0x0B
        uint8_t xD = xtime(xtime(xtime(x)) ^ xtime(x)) ^ x; // Multiply x by 0x0D
        uint8_t x9 = xtime(xtime(xtime(x))) ^ x;            // Multiply x by 0x09

        T0[i] = (xE << 24) | (x9 << 16) | (xD << 8) | xB;
        T1[i] = (xB << 24) | (xE << 16) | (x9 << 8) | xD;
        T2[i] = (xD << 24) | (xB << 16) | (xE << 8) | x9;
        T3[i] = (x9 << 24) | (xD << 16) | (xB << 8) | xE;
    }
}
void init_tables()
{
    // compute encryption lookup tables
    compute_encTables(te0, te1, te2, te3);

    // compute decryption lookup tables
    compute_decTables(td0, td1, td2, td3);

}

const uint8_t RC[10] = {0x01 , 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};


uint32_t rotWord(uint32_t word)
{
    uint8_t left_byte = (word & 0xff000000) >> 24;

    uint32_t outputWord = (word << 8) | left_byte;
    return outputWord;
}

uint32_t subWord(uint32_t word)
{
    uint32_t outputWord = 0;
    for(int i=0; i<4; i++)
    {
        uint8_t input_of_s_box = (word >> (8 * i)) & 0x000000ff;

        uint8_t input_of_s_box_row = input_of_s_box >> 4;

        uint8_t input_of_s_box_col = input_of_s_box & 0x0f;

        outputWord |=  AES_Sbox[(input_of_s_box_row * 16) + input_of_s_box_col] << (8 * i);
    }
    return outputWord;
}
uint32_t Rcon(uint32_t round_no)
{
    uint32_t output = RC[round_no - 1];
    output = output << 24;
    return output;
}

uint32_t* KeyExpansion (uint32_t key[4])
 {
     static uint32_t wordw[44]={0};
     uint32_t wordtemp = 0;
     for(int i = 0; i < 4; i++)
         {
             wordw[i] = key[i];
         }

     for(int i = 4; i < 44; i++)
     {
         uint32_t temp = wordw[i-1];
         if(i % 4 == 0)
         {
            temp = subWord (rotWord (temp)) ^ Rcon(i/4);
         }
         wordw[i] = wordw[i-4] ^ temp;
     }
     return wordw;
 }

uint32_t* addRoundKey(uint32_t input[4], uint32_t key[4])
{
    static uint32_t output[4] = {0};
    for(int i=0;i<4;i++)
    {
        output[i] = input[i] ^ key[i];
    }
    return output;
}

uint32_t* reverse_key(uint32_t w[44]){
	static uint32_t output[44] = {0};
	for(int i=40;i>=0;i=i-4){
		output[i]   = w[40-i];
		output[i+1] = w[41-i];
		output[i+2] = w[42-i];
		output[i+3] = w[43-i];
	}
	return output;
}

uint32_t* invMixColumns(uint32_t w[44]){
    uint32_t mul = 0x0E0B0D09;
    uint32_t count = 0;
    for(int i=4;i<40;i=i+4){
        uint8_t result[16] = {0};
        uint8_t x = 0;
        for(int e=0;e<4;e++){
        for(int k=i;k<i+4;k++){
            uint32_t res = 0;
            for(int j=0;j<4;j++){
                uint32_t mulresult = 0;
                uint32_t val1 = mul>>(24-j*8)&0xff ;
                uint32_t val2 = w[k]>>(24-j*8)&0xff;
                uint32_t index = 0;
                uint32_t val1cpy = val1;
                while(val1cpy!=0){
                    if(index==0){
                        if(val1cpy & 0x1){
                            mulresult = val2;
                        }
                    }
                    else{
                        val2 = (val2>>7 & 0x1)? (((val2<<1) & 0xff) ^ 0x1B): (val2<<1 & 0xff);
                        if(val1cpy & 0x1){
                            mulresult^=val2;
                        }
                    }
                    index++;
                    val1cpy = val1cpy>>1;
                }
                res=res^mulresult;
            }
            result[x] = res;
            x++;
        }
        mul = ((mul & 0xff)<<24) |  (mul>>8);
        }
        int k = 0;
        for(int q=i;q<i+4;q++){
             w[q] = result[k]<<24 | result[k+4]<<16 | result[k+8]<<8 | result[k+12];
             k++;
        }


    }
    return w;
}


uint32_t* AES_Encryption_Decryption(uint32_t input[4], uint32_t key[4],uint8_t type)
{

	uint32_t *w = KeyExpansion(key);
	if(type == 'd'){
		w = reverse_key(w);
        w = invMixColumns(w);
	}
	uint32_t first_key[4] = {w[0],w[1],w[2],w[3]};
    uint32_t *state = addRoundKey(input,first_key);

    for(int i=0;i<9;i++)
    {
		uint32_t col[4] = {0};
        for(int j=0;j<4;j++)
        {
			if(type == 'e'){
            	col[j] = te0[(state[j] >> 24)] ^ te1[(state[(j+1)%4]>>16) & 0xff] ^ te2[(state[(j+2)%4]>>8) & 0xff] ^ te3[state[(j+3)%4] & 0xff] ^ w[((i+1)*4)+j];
            }
			else if(type == 'd'){
				col[j] = td0[(state[j] >> 24)] ^ td1[(state[(j+3)%4]>>16) & 0xff] ^ td2[(state[(j+2)%4]>>8) & 0xff] ^ td3[state[(j+1)%4] & 0xff] ^ w[((i+1)*4)+j];
			}
		}
		for(int k=0;k<4;k++){
			state[k] = col[k];
		}
    }
	uint32_t sub_output[4] = {0};
	uint32_t shift_output[4] = {0};
	if(type == 'e'){
		//substitute
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++){
				sub_output[i] |= AES_Sbox[(state[i]>>(24-j*8) & 0x0f) + (state[i]>>(24-j*8)>>4 & 0x0f)*16]<<(24-j*8);
			}
		}
		//shift rows
		for(int i=0;i<4;i++){
			shift_output[i] |= (sub_output[i] & 0xff000000) | (sub_output[(i+1)%4] & 0x00ff0000) | (sub_output[(i+2)%4] & 0x0000ff00) | (sub_output[(i+3)%4] & 0x000000ff);
		}
	}
	else if(type == 'd'){
		//shift rows
		for(int i=0;i<4;i++){
			shift_output[i] |= (state[i] & 0xff000000) | (state[(i+1)%4] & 0x000000ff) | (state[(i+2)%4] & 0x0000ff00) | (state[(i+3)%4] & 0x00ff0000);
		}
		//substitute
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++){
				sub_output[i] |= AES_InvSbox[(shift_output[i]>>(24-j*8) & 0x0f) + (shift_output[i]>>(24-j*8)>>4 & 0x0f)*16]<<(24-j*8);
			}
		}
	}
	uint32_t final_key[4] =  {w[40],w[41],w[42],w[43]};
	if(type == 'e'){
		state = addRoundKey(shift_output,final_key);
	}
	else if(type == 'd'){
		state = addRoundKey(sub_output,final_key);
	}
	return state;
}

/*

int main()
{
    init_tables();
    uint32_t key1[4] = { 0x0f1571c9 , 0x47d9e859 , 0x0cb7add6 , 0xaf7f6798} ;
    uint32_t plaintext[4] = {0x01234567,0x89abcdef,0xfedcba98,0x76543210};
	uint32_t key2[4] = { 0x0f1571c9 , 0x47d9e859 , 0x0cb7add6 , 0xaf7f6798} ;
	uint32_t cipherText[4] = {0xff0b844a,0x0853bf7c,0x6934ab43,0x64148fb9};
    char x = 'e';
    if (x == 'e'){
        uint32_t *output1 = AES_Encryption_Decryption(plaintext,key1,'e');
        printf("Cipher : ");
        for(int i=0;i<4;i++){
            printf("0x%x ",output1[i]);
        }
        printf("\n");
        printf("**************************************************************************************\n");

        uint32_t *output2 = AES_Encryption_Decryption(cipherText,key2,'d');
        printf("plain : ");
        for(int i=0;i<4;i++){
            printf("0x%x ",output2[i]);
        }
        printf("\n");
        printf("**************************************************************************************\n");
    }

    else{
        uint32_t *output2 = AES_Encryption_Decryption(cipherText,key2,'d');
        printf("plain : ");
        for(int i=0;i<4;i++){
            printf("0x%x ",output2[i]);
        }
        printf("\n");
        printf("**************************************************************************************\n");
    }
    return 0;
}
//key :0f1571c947d9e8590cb7add6af7f6798
//plaintext: 0123456789abcdeffedcba9876543210
//ciphertext: ff0b844a0853bf7c6934ab4364148fb9
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16



// Helper function to convert uint8_t[16] to uint32_t[4]
void bytes_to_uint32_array(const uint8_t *bytes, uint32_t *array) {
    for (int i = 0; i < 4; i++) {
        array[i] = ((uint32_t)bytes[i * 4] << 24) |
                   ((uint32_t)bytes[i * 4 + 1] << 16) |
                   ((uint32_t)bytes[i * 4 + 2] << 8) |
                   (uint32_t)bytes[i * 4 + 3];
    }
}

// Helper function to convert uint32_t[4] to uint8_t[16]
void uint32_array_to_bytes(const uint32_t *array, uint8_t *bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[i * 4] = (array[i] >> 24) & 0xFF;
        bytes[i * 4 + 1] = (array[i] >> 16) & 0xFF;
        bytes[i * 4 + 2] = (array[i] >> 8) & 0xFF;
        bytes[i * 4 + 3] = array[i] & 0xFF;
    }
}

void process_file(const char *input_file, const char *output_file, const char *key_file, char mode) {
    FILE *key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        perror("Error opening key file");
        exit(1);
    }

    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        perror("Error opening input file");
        fclose(key_fp);
        exit(1);
    }

    FILE *output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        perror("Error opening output file");
        fclose(key_fp);
        fclose(input_fp);
        exit(1);
    }

    // Read the 128-bit key (16 bytes) and convert it to uint32_t[4]
    uint8_t key_bytes[AES_BLOCK_SIZE];
    uint32_t key[4];
    if (fread(key_bytes, 1, AES_BLOCK_SIZE, key_fp) != AES_BLOCK_SIZE) {
        perror("Error reading key file");
        fclose(key_fp);
        fclose(input_fp);
        fclose(output_fp);
        exit(1);
    }
    bytes_to_uint32_array(key_bytes, key);

    uint8_t block_bytes[AES_BLOCK_SIZE];
    uint32_t block[4];
    size_t bytes_read;

    while ((bytes_read = fread(block_bytes, 1, AES_BLOCK_SIZE, input_fp)) > 0) {
        // Pad the last block with zeros for encryption
        if (bytes_read < AES_BLOCK_SIZE && mode == 'e') {
            memset(block_bytes + bytes_read, 0, AES_BLOCK_SIZE - bytes_read);
        }

        // Convert bytes to uint32_t[4] and process the block
        bytes_to_uint32_array(block_bytes, block);
        AES_Encryption_Decryption(block, key, mode);

        // Convert the processed block back to bytes and write to output
        uint32_array_to_bytes(block, block_bytes);
        fwrite(block_bytes, 1, AES_BLOCK_SIZE, output_fp);
    }

    fclose(key_fp);
    fclose(input_fp);
    fclose(output_fp);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s <e|d> <key_file> <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    char mode = argv[1][0];
    if (mode != 'e' && mode != 'd') {
        printf("Invalid mode. Use 'e' for encryption or 'd' for decryption.\n");
        return 1;
    }

    process_file(argv[3], argv[4], argv[2], mode);

    return 0;
}


