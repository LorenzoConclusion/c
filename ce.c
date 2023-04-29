#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

// SHA256 hash length
#define SHA256_HASH_LEN 65

// Max transaction length
#define MAX_TRANS_LENGTH 150

// Max transactions
#define MAX_TRANS 10

// Transaction block struct
typedef struct trans_block {
    int index;
    char trans[MAX_TRANS_LENGTH + 1];
    char prev_hash[SHA256_HASH_LEN + 1];
    char hash[SHA256_HASH_LEN + 1];
    time_t timestamp;
} trans_block;

// PendingList struct
typedef struct PendingList {
    trans_block *transactions;
    int count;
} PendingList;

// Global transaction chain array
struct trans_block trans_chain[MAX_TRANS];

// Current transaction index
int current_index = 0;

// Calculate SHA256 hash
void sha256(char *string, char *output) {
unsigned char hash[SHA256_DIGEST_LENGTH];
SHA256_CTX sha256;
SHA256_Init(&sha256);
SHA256_Update(&sha256, string, strlen(string));
SHA256_Final(hash, &sha256);

char outputBuffer[SHA256_DIGEST_LENGTH * 2 + 1]; 
for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) { 
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]); 
} 
strcpy(output, outputBuffer); 
}

// Add new transaction block
void add_trans_block(char *trans) {
struct trans_block new_block;
new_block.index = current_index;
strncpy(new_block.trans, trans, MAX_TRANS_LENGTH);
new_block.trans[MAX_TRANS_LENGTH] = '\0';
new_block.timestamp = time(NULL);

// Set prev_hash to previous block's hash 
if (current_index > 0) { 
    strcpy(new_block.prev_hash, trans_chain[current_index - 1].hash); 
} else { 
    strcpy(new_block.prev_hash, ""); 
} 

sha256((char *)&new_block, new_block.hash); 
trans_chain[current_index++] = new_block; 
}

// Print transaction chain
void print_trans_chain() {
// Print details of each block in the chain
for (int i = 0; i < current_index; i++) {
printf("Block %d:\n", trans_chain[i].index);
printf("Transaction: %s\n", trans_chain[i].trans);
printf("Timestamp: %s", ctime(&trans_chain[i].timestamp));
printf("Previous Hash: %s\n", trans_chain[i].prev_hash);
printf("Hash: %s\n", trans_chain[i].hash);
printf("\n");
}
char filename[] = "blockchain.txt";
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        printf("Error: could not open file %s\n", filename);
        exit(1);
    }
    for (int i = 0; i < current_index; i++) {
      fprintf(f, "Index: %d\nTransaction: %s\nTimestamp: %sHash: %s\nPrevious Hash: %s\n\n",
        trans_chain[i].index, trans_chain[i].trans, ctime(&trans_chain[i].timestamp),
        trans_chain[i].hash, trans_chain[i].prev_hash);    }
    fclose(f);
}

// Function to find a trans block by index
struct trans_block *find_trans_block(int index) {
if (index >= 0 && index < current_index) {
return &trans_chain[index];
}
return NULL;
}

int main() {
int choice, index;
char trans[MAX_TRANS_LENGTH + 1];

do { 
    printf("Transcations Manager Menu:\n"); 
    printf("1. Add a trans\n"); 
    printf("2. See all transs\n"); 
    printf("5. Quit\n"); 
    printf("Enter your choice (1-5): "); 
    scanf("%d", &choice); 

    switch (choice) { 
        case 1: 
            printf("Enter a trans (maximum %d characters): ", MAX_TRANS_LENGTH); 
            scanf("%s", trans); 
            add_trans_block(trans); 
            printf("Transcations added successfully.\n\n"); 
            break; 
        case 2: 
            printf("Transcations Chain:\n"); 
            print_trans_chain(); 
            break; 
        case 5: 
            printf("Goodbye!\n"); 
            break; 
        default: 
            printf("Invalid choice. Please choose a number between 1 and 5.\n\n"); 
            break; 
    } 
} while (choice != 5); 

return 0; 
}
