#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

// Prime checking for secure prime generation
int is_prime(int num) {
    if (num <= 1) return 0;
    if (num <= 3) return 1;
    if (num % 2 == 0 || num % 3 == 0) return 0;
    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0)
            return 0;
    }
    return 1;
}

// Generate large random prime numbers for RSA
int generate_prime(int limit) {
    int prime;
    do {
        prime = rand() % limit + 2; // Start from 2
    } while (!is_prime(prime));
    return prime;
}

// Calculate gcd for e and phi check
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Fast modular exponentiation function
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Struct to hold RSA keys
struct RSAKeys {
    int public_key;  // e
    int private_key; // d
    int modulus;     // n
};

// Generate RSA keys for encryption and digital signatures
struct RSAKeys generate_keys() {
    struct RSAKeys keys;
    int p = generate_prime(1000);
    int q;
    do {
        q = generate_prime(1000);
    } while (q == p);  // Ensure p and q are distinct primes
    keys.modulus = p * q;
    int phi = (p - 1) * (q - 1);

    // Select public key `e` coprime to `phi`
    keys.public_key = 3;
    while (gcd(keys.public_key, phi) != 1) {
        keys.public_key++;
    }

    // Calculate private key `d`
    int k = 1;
    while ((1 + k * phi) % keys.public_key != 0) {
        k++;
    }
    keys.private_key = (1 + k * phi) / keys.public_key;

    printf("Generated RSA keys:\nPublic key (e): %d\nPrivate key (d): %d\nModulus (n): %d\n", 
            keys.public_key, keys.private_key, keys.modulus);
    return keys;
}

// Encrypt message with RSA
int encrypt(int message, int public_key, int modulus) {
    return mod_exp(message, public_key, modulus);
}

// Decrypt message with RSA
int decrypt(int ciphertext, int private_key, int modulus) {
    return mod_exp(ciphertext, private_key, modulus);
}

// Simple hash function (upgradeable to SHA for advanced security)
unsigned int simple_hash(const char *message) {
    unsigned int hash = 0;
    int i = 0;
    while (message[i] != '\0') {
        hash = (hash << 5) + (unsigned char)message[i];
        i++;
    }
    return hash;
}

// Sign message hash with private key
int sign_message(unsigned int message_hash, int private_key, int modulus) {
    return mod_exp(message_hash, private_key, modulus);
}

// Verify digital signature using the public key
int verify_signature(int signature, int public_key, int modulus, unsigned int original_message_hash) {
    int decrypted_hash = mod_exp(signature, public_key, modulus);
    return decrypted_hash == original_message_hash;
}

int main() {
    srand((unsigned int)time(NULL));
    struct RSAKeys keys;
    int choice;

    int last_encrypted_message = -1;
    int last_ciphertext = -1;

    // Variables to store the signature and message hash for verification
    int saved_signature = -1;
    unsigned int saved_message_hash = 0;

    do {
        printf("\nRSA Cryptography Menu:\n");
        printf("1. Generate Keys\n");
        printf("2. Encrypt Message\n");
        printf("3. Decrypt Last Encrypted Message\n");
        printf("4. Sign Message\n");
        printf("5. Verify Signature\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                keys = generate_keys();
                break;

            case 2: {
                int message;
                printf("Enter a numeric message to encrypt: ");
                scanf("%d", &message);
                last_ciphertext = encrypt(message, keys.public_key, keys.modulus);
                last_encrypted_message = message;
                printf("Encrypted message: %d\n", last_ciphertext);
                break;
            }

            case 3: {
                if (last_ciphertext == -1) {
                    printf("No encrypted message found. Please encrypt a message first.\n");
                } else {
                    int decrypted_message = decrypt(last_ciphertext, keys.private_key, keys.modulus);
                    printf("Decrypted message: %d\n", decrypted_message);
                    if (decrypted_message == last_encrypted_message) {
                        printf("Decrypted message matches the original message: %d\n", last_encrypted_message);
                    } else {
                        printf("Decrypted message does not match the original message.\n");
                    }
                }
                break;
            }

            case 4: {
                char msg[100];
                printf("Enter a message to sign: ");
                getchar(); // To consume the newline character left by previous input
                fgets(msg, 100, stdin);
                msg[strcspn(msg, "\n")] = 0;

                saved_message_hash = simple_hash(msg);
                printf("Message hash: %u\n", saved_message_hash);

                saved_signature = sign_message(saved_message_hash, keys.private_key, keys.modulus);
                printf("Signature: %d\n", saved_signature);
                break;
            }

            case 5: {
                if (saved_signature == -1) {
                    printf("No signature found. Please sign a message first.\n");
                } else {
                    char msg[100];
                    printf("Enter the original message for verification: ");
                    getchar(); // To consume the newline character left by previous input
                    fgets(msg, 100, stdin);
                    msg[strcspn(msg, "\n")] = 0;

                    unsigned int message_hash = simple_hash(msg);

                    if (verify_signature(saved_signature, keys.public_key, keys.modulus, message_hash)) {
                        printf("Signature verification successful.\n");
                    } else {
                        printf("Signature verification failed.\n");
                    }
                }
                break;
            }

            case 6:
                printf("Exiting...\n");
                break;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 6);

    return 0;
}
