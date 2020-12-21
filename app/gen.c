
#include <stdio.h>
#include <time.h>

#include <sodium.h>
#include "cifer/test.h"
#include "cifer/internal/common.h"
#include "cifer/abe/gpsw.h"
#include "cifer/serialization/data_ser.h"

#define MESSAGE (const unsigned char *) "test\0"
#define MESSAGE_LEN 5

// read and test written GPSW keys
void check_written_keys(const char* filename, size_t len, cfe_gpsw_keys *keys) {
    cfe_ser buf2;
    buf2.len = len;
    buf2.ser = malloc(sizeof(uint8_t) * buf2.len);

    // read back data
    FILE *fp = fopen(filename, "r");
    munit_assert_not_null(fp);

    size_t bytes = fread(buf2.ser, sizeof(uint8_t), buf2.len, fp);
    fclose(fp);
    munit_assert(bytes > 0);

    cfe_gpsw_keys keys2;
    cfe_gpsw_keys_read(&keys2, &buf2);

    munit_assert(keys->mat.rows == keys2.mat.rows);
    munit_assert(keys->mat.cols == keys2.mat.cols);
    for (size_t i =0; i<keys->mat.rows; i++) {
        munit_assert(keys->row_to_attrib[i] == keys2.row_to_attrib[i]);
        for (size_t j =0; j < keys->mat.cols; j++) {
            munit_assert(mpz_cmp(keys->mat.mat[i].vec[j], keys2.mat.mat[i].vec[j]) == 0);
        }
    }
    munit_assert(keys->d.size == keys2.d.size);
    for (size_t i = 0; i < keys->d.size; i++) {
        munit_assert(ECP_BN254_equals(&keys->d.vec[i], &keys2.d.vec[i]) == 1);
    }

    cfe_ser_free(&buf2);
}

void seed_rng(csprng *RNG)
{
    int i;
    char pr[10];
    unsigned long ran;

    time((time_t *)&ran);
    pr[0] = ran;
    pr[1] = ran >> 8;
    pr[2] = ran >> 16;
    pr[3] = ran >> 24;
    for (i = 4; i < 10; i++)
        pr[i] = i;
    RAND_seed(RNG, 10, pr);
}

int main(int argc, char *argv[]) {
    if (cfe_init()) {
        perror("Insufficient entropy available for random generation\n");
        return CFE_ERR_INIT;
    }

    cfe_gpsw_pub_key pk;
    cfe_gpsw gpsw;
    cfe_ser buf;
    cfe_vec sk;
    FILE *fp;

    cfe_gpsw_init(&gpsw, 10);
    cfe_gpsw_master_keys_init(&pk, &sk, &gpsw);
    cfe_gpsw_generate_master_keys(&pk, &sk, &gpsw);

    cfe_gpsw_pub_key_ser(&pk, &buf);

    printf("GPSW public key serialized (%ld bytes)\n", buf.len);
    if (buf.len == 0) {
        perror("Nothing to serialize... Check your parameters");
        return -1;
    }

    // write in file
    fp = fopen("gpsw_pk.key", "w");
    if (fp == NULL) {
        perror("Unable to open file to serialize GPSW public key");
        return -1;
    }
    fwrite(buf.ser, sizeof(uint8_t), buf.len, fp);
    fclose(fp);

    // read and test written public key
    {
        cfe_ser buf2;
        buf2.len = buf.len;
        buf2.ser = malloc(sizeof(uint8_t) * buf2.len);

        // read back data
        fp = fopen("gpsw_pk.key", "r");
        if (fp == NULL) {
            perror("Unable to open file to serialize GPSW public key");
            return -1;
        }
        size_t bytes = fread(buf2.ser, sizeof(uint8_t), buf2.len, fp);
        fclose(fp);
        if (bytes <= 0) {
            perror("No bytes read from the file of public key");
            return -1;
        }

        cfe_gpsw_pub_key pk2;
        cfe_gpsw_pub_key_read(&pk2, &buf2);

        munit_assert(pk.t.size == pk2.t.size);
        for (size_t i = 0; i < pk.t.size; i++) {
            int check = ECP2_BN254_equals(&pk.t.vec[i], &pk2.t.vec[i]);
            munit_assert(check == 1);
        }

        cfe_ser_free(&buf2);
    }
    cfe_ser_free(&buf);

    // produce attribute based keys

    // create a msp struct out of a boolean expression representing the
    // policy specifying which attributes are needed to decrypt the ciphertext
    /* let's say we need all attributes to decrypt data */
    char bool_exp[] = "1 AND 2";
    size_t bool_exp_len = 7; // length of the boolean expression string
    cfe_msp msp;
    cfe_error err = cfe_boolean_to_msp(&msp, bool_exp, bool_exp_len, true);
    if (err != CFE_ERR_NONE) {
        printf("FAILURE - there should be no policy parsing error\n");
        return 1;
    }

    // generate keys for decryption that correspond to provided msp struct,
    // i.e. a vector of keys, for each row in the msp matrix one key, having
    // the property that a subset of keys can decrypt a message iff the
    // corresponding rows span the vector of ones (which is equivalent to
    // corresponding attributes satisfy the boolean expression)
    cfe_vec_G1 policy_keys;
    cfe_gpsw_policy_keys_init(&policy_keys, &msp);
    cfe_gpsw_generate_policy_keys(&policy_keys, &gpsw, &msp, &sk);

    /* keys for client that does NOT have the right to decrypt */
    cfe_gpsw_keys keys_fail;
    {
        // produce a set of keys that are given to an entity with a set
        // of attributes in owned_attrib
        int owned_attrib[] = {1};
        cfe_gpsw_keys_init(&keys_fail, &msp, owned_attrib, 1);
        cfe_gpsw_delegate_keys(&keys_fail, &policy_keys, &msp, owned_attrib, 1);

        cfe_ser keys_buf;
        cfe_gpsw_keys_ser(&keys_fail, &keys_buf);

        printf("GPSW keys for 'open access' serialized (%ld bytes)\n", keys_buf.len);
        if (keys_buf.len == 0) {
            perror("Nothing to serialize... Check your parameters");
            return -1;
        }

        // write in file
        fp = fopen("gpsw_open_access.key", "w");
        if (fp == NULL) {
            perror("Unable to open file to serialize GPSW public key");
            return -1;
        }
        fwrite(keys_buf.ser, sizeof(uint8_t), keys_buf.len, fp);
        fclose(fp);

        check_written_keys("gpsw_open_access.key", keys_buf.len, &keys_fail);
        cfe_ser_free(&keys_buf);
    }

    /* keys for client that does have the right to decrypt */
    cfe_gpsw_keys keys_ok;
    {
        // produce a set of keys that are given to an entity with a set
        // of attributes in owned_attrib
        int owned_attrib[] = {1, 2};
        cfe_gpsw_keys_init(&keys_ok, &msp, owned_attrib, 2);
        cfe_gpsw_delegate_keys(&keys_ok, &policy_keys, &msp, owned_attrib, 2);

        cfe_ser keys_buf;
        cfe_gpsw_keys_ser(&keys_ok, &keys_buf);

        printf("GPSW keys for 'restricted access' serialized (%ld bytes)\n", keys_buf.len);
        if (keys_buf.len == 0) {
            perror("Nothing to serialize... Check your parameters");
            return -1;
        }

        // write in file
        fp = fopen("gpsw_restricted_access.key", "w");
        if (fp == NULL) {
            perror("Unable to open file to serialize GPSW public key");
            return -1;
        }
        fwrite(keys_buf.ser, sizeof(uint8_t), keys_buf.len, fp);
        fclose(fp);

        check_written_keys("gpsw_restricted_access.key", keys_buf.len, &keys_ok);
        cfe_ser_free(&keys_buf);
    }

    printf("Encrypt/decrypt string message\n");

    // Define a set of attributes (a subset of the universe of attributes)
    // that will later be used in the decryption policy of the message
    /* Two attributes here: 'general access' and 'restricted access' */
    int gamma[] = {1, 2};

    // Generate AES key
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES] = {0};
    unsigned char ciphertext[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];
    unsigned long long ciphertext_len;
    // crypto_aead_aes256gcm_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    // generate a random used as AES key
    csprng RNG;
    seed_rng(&RNG);

    // create a message to be encrypted
    BIG_256_56 big_key, order;
    BIG_256_56_rcopy(order, CURVE_Order_BN254);
    BIG_256_56_randomnum(big_key, order, &RNG);

    FP12_BN254 msg;
    FP4_BN254 fp4;
    FP2_BN254 fp2;
    FP2_BN254_from_BIG(&fp2, big_key);
    FP4_BN254_from_FP2(&fp4, &fp2);
    FP12_BN254_from_FP4(&msg, &fp4);

    // setup key
    BIG_256_56_toBytes((char*)key, big_key);

    crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len, MESSAGE, MESSAGE_LEN,
                                NULL, 0, NULL, nonce, key);

    printf("AES ciphertext len: %lld bytes\n", ciphertext_len);

    // encrypt the message
    cfe_gpsw_cipher cipher;
    cfe_gpsw_cipher_init(&cipher, 2);
    cfe_gpsw_encrypt(&cipher, &gpsw, &msg, gamma, 2, &pk);

    printf("Encryption OK\n");

    // writing ciphertext down to file and load it back
    cfe_gpsw_cipher_ser(&cipher, &buf);

    printf("GPSW ciphertext serialized (%ld bytes)\n", buf.len);
    if (buf.len == 0) {
        perror("Nothing to serialize... Check your parameters");
        return -1;
    }

    // write in file
    fp = fopen("gpsw_ciphertext.raw", "w");
    if (fp == NULL) {
        perror("Unable to open file to serialize GPSW public key");
        return -1;
    }
    fwrite(buf.ser, sizeof(uint8_t), buf.len, fp);
    fclose(fp);

    {
        cfe_ser buf2;
        buf2.len = buf.len;
        buf2.ser = malloc(sizeof(uint8_t) * buf2.len);

        // read back data
        fp = fopen("gpsw_ciphertext.raw", "r");
        if (fp == NULL) {
            perror("Unable to open file to serialize GPSW public key");
            return -1;
        }
        size_t bytes = fread(buf2.ser, sizeof(uint8_t), buf2.len, fp);
        fclose(fp);
        if (bytes <= 0) {
            perror("No bytes read from the file of public key");
            return -1;
        }

        cfe_gpsw_cipher cipher2;
        cfe_gpsw_cipher_read(&cipher2, &buf2);

        munit_assert(FP12_BN254_equals(&cipher.e0, &cipher2.e0) == 1);
        munit_assert(cipher.e.size == cipher2.e.size);
        for (size_t i = 0; i < cipher.e.size; i++) {
            munit_assert(cipher.gamma[i] == cipher2.gamma[i]);
            int check = ECP2_BN254_equals(&cipher.e.vec[i], &cipher2.e.vec[i]);
            munit_assert(check == 1);
        }

        cfe_ser_free(&buf2);
    }

    // verify decryption fail with 'open access' keys
    {
        cfe_gpsw gpsw_dec;
        cfe_gpsw_init(&gpsw_dec, 10);

        FP12_BN254 decrypted;
        cfe_error err_dec = cfe_gpsw_decrypt(&decrypted, &cipher, &keys_fail, &gpsw_dec);
        if (err_dec == CFE_ERR_NONE) {
            printf("This should fail !\n");
            return -1;
        }
    }

    // verify decryption succeed with 'restricted access' keys
    {
        cfe_gpsw gpsw_dec;
        cfe_gpsw_init(&gpsw_dec, 10);

        FP12_BN254 dec_msg;
        cfe_error err_dec = cfe_gpsw_decrypt(&dec_msg, &cipher, &keys_ok, &gpsw_dec);
        if (err_dec != CFE_ERR_NONE) {
            printf("Error decrypting GPSW struct !\n");
            return -1;
        }

        if (FP12_BN254_equals(&msg, &dec_msg) != 1) {
            printf("FAILURE - FP12 messages are not equal\n");
            return -1;
        }

        unsigned char key_dec[crypto_aead_aes256gcm_KEYBYTES];
        BIG_256_56 rec_big;
        BIG_256_56_zero(rec_big);
        FP_BN254_redc(rec_big, &dec_msg.a.a.a);
        BIG_256_56_toBytes((char*)key_dec, rec_big);

        munit_assert(memcmp(key, key_dec, crypto_aead_aes256gcm_KEYBYTES) == 0);

        unsigned char decrypted[MESSAGE_LEN];
        unsigned long long decrypted_len;
        if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
            crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                        NULL, ciphertext, ciphertext_len,
                                        NULL, 0, nonce, key_dec) != 0) {
            /* message forged! */
            printf("Error decrypting with AES !\n");
            return -1;
        }

        munit_assert(decrypted_len == MESSAGE_LEN);
        munit_assert(memcmp(decrypted, MESSAGE, MESSAGE_LEN) == 0);

        printf("Decryption OK\n");
    }

    printf("All good !\n");

    // clean
    cfe_ser_free(&buf);
    cfe_gpsw_pub_key_free(&pk);
    cfe_vec_free(&sk);
    cfe_gpsw_free(&gpsw);
    return 0;
}