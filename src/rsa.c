#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>

struct rsa_ctx {
    BIGNUM *sk;
    BIGNUM *pk;
    BIGNUM *n;
};

void rsa_encrypt(struct rsa_ctx * ctx, BIGNUM *ctxt, const BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(ctxt, ptxt, ctx->pk, ctx->n, bnctx);
}

void rsa_decrypt(struct rsa_ctx * ctx, BIGNUM *ptxt, BIGNUM *ctxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(ptxt, ctxt, ctx->sk, ctx->n, bnctx);
}

void rsa_sign(struct rsa_ctx * ctx, BIGNUM *S, BIGNUM *H) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(S, H, ctx->sk, ctx->n, bnctx);
}

int rsa_verify(struct rsa_ctx * ctx, BIGNUM *S, BIGNUM *H) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *tmp;
    tmp = BN_new();
    BN_mod_exp(tmp, S, ctx->pk, ctx->n, bnctx);

    if (BN_cmp(tmp, H) == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

void pkg_pk(struct rsa_ctx * ctx, struct rsa_ctx *Sctx, char * prefix) {
    char *pkfilename[256];
    char *pknum[4];
    char *nnum[3];
    char *Spknum[4];
    char *Snnum[3];
    FILE *pkfile;
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int nbytes = BN_num_bytes(ctx->n);
    int Spkbytes = BN_num_bytes(Sctx->pk);
    int Snbytes = BN_num_bytes(Sctx->n);
    sprintf(pknum, "%d", pkbytes);
    sprintf(nnum, "%d", nbytes);
    sprintf(Spknum, "%d", Spkbytes);
    sprintf(Snnum, "%d", Snbytes);
    unsigned char *pk[pkbytes];
    unsigned char *n[nbytes];
    unsigned char *Spk[Spkbytes];
    unsigned char *Sn[Snbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->n, n);
    BN_bn2bin(Sctx->pk, Spk);
    BN_bn2bin(Sctx->n, Sn);
    pkfile = fopen(pkfilename, "wb");
    fwrite(pknum, 1, strlen(pknum), pkfile);
    fwrite(pk, 1, pkbytes, pkfile);
    fwrite(nnum, 1, strlen(nnum), pkfile);
    fwrite(n, 1, nbytes, pkfile);
    fwrite(pknum, 1, strlen(pknum), pkfile);
    fwrite(Spk, 1, Spkbytes, pkfile);
    fwrite(Snnum, 1, strlen(Snnum), pkfile);
    fwrite(Sn, 1, Snbytes, pkfile);
    fclose(pkfile);
}

void pkg_sk(struct rsa_ctx * ctx, char * prefix) {
    char *skfilename[256];
    char *sknum[4];
    FILE *tmpfile;
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int skbytes = BN_num_bytes(ctx->sk);
    sprintf(sknum, "%d", skbytes);
    unsigned char *sk[skbytes];
    BN_bn2bin(ctx->sk, sk);
    tmpfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), tmpfile);
    fwrite(sk, 1, skbytes, tmpfile);
    fclose(tmpfile);
}

void pkg_keys(struct rsa_ctx * ctx, char * prefix) {
    char pkfilename[256];
    char skfilename[256];
    char pknum[4];
    char sknum[4];
    char nnum[3];
    FILE *tmpfile;
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int skbytes = BN_num_bytes(ctx->sk);
    int nbytes = BN_num_bytes(ctx->n);
    sprintf(pknum, "%d", pkbytes);
    sprintf(sknum, "%d", skbytes);
    sprintf(nnum, "%d", nbytes);
    unsigned char pk[pkbytes];
    unsigned char sk[skbytes];
    unsigned char n[nbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->sk, sk);
    BN_bn2bin(ctx->n, n);
    tmpfile = fopen(pkfilename, "wb");
    fwrite(pknum, 1, strlen(pknum), tmpfile);
    fwrite(pk, 1, pkbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fclose(tmpfile);
    tmpfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), tmpfile);
    fwrite(sk, 1, skbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fclose(tmpfile);
}

int pkg_sk_bytes_count(struct rsa_ctx *ctx, struct rsa_ctx *Sctx) {
    int sknum = 4;
    int Ssknum = 4;
    int nnum = 3;
    int nbytes = BN_num_bytes(ctx->n);
    int skbytes = BN_num_bytes(ctx->sk);
    int Snbytes = BN_num_bytes(Sctx->n);
    int Sskbytes = BN_num_bytes(Sctx->sk);
    int total = ((nnum * 2) + (nbytes * 2) + sknum + Ssknum + skbytes + Sskbytes);
    return total;
}

void pkg_sk_bytes(struct rsa_ctx * ctx, struct rsa_ctx *Sctx, unsigned char *keyblob) {
    char *nnum[3];
    char *sknum[4];
    char *Snnum[3];
    char *Ssknum[4];
    int nbytes = 768;
    sprintf(nnum, "%d", nbytes);
    int skbytes = 1536;
    sprintf(sknum, "%d", skbytes);
    int Snbytes = 768;
    sprintf(Snnum, "%d", Snbytes);
    int Sskbytes = 1536;
    sprintf(Ssknum, "%d", Sskbytes);
    int tt = atoi(sknum);
    unsigned char n[nbytes];
    BN_bn2bin(ctx->n, n);
    unsigned char sk[skbytes];
    BN_bn2bin(ctx->sk, sk);
    int Stt = atoi(Ssknum);
    unsigned char Sn[Snbytes];
    BN_bn2bin(Sctx->n, n);
    unsigned char Ssk[Sskbytes];
    BN_bn2bin(Sctx->sk, Ssk);
    int pos = 0;
    int i;
    unsigned char *_nnum = (unsigned char *)nnum;
    unsigned char *_sknum = (unsigned char *)sknum;
    unsigned char *_Snnum = (unsigned char *)Snnum;
    unsigned char *_Ssknum = (unsigned char *)Ssknum;
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _nnum[i];
        pos += 1;
    }
    for (i = 0; i < nbytes; i++) {
        keyblob[pos] = n[i];
        pos += 1;
    }
    for (i = 0; i < 4; i++) {
        keyblob[pos] = _sknum[i];
        pos += 1;
    }
    for (i = 0; i < skbytes; i++) {
        keyblob[pos] = sk[i];
        pos += 1;
    }
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _nnum[i];
        pos += 1;
    }
    for (i = 0; i < Snbytes; i++) {
        keyblob[pos] = Sn[i];
        pos += 1;
    }
    for (i = 0; i < 4; i++) {
        keyblob[pos] = _Ssknum[i];
        pos += 1;
    }
    for (i = 0; i < Sskbytes; i++) {
        keyblob[pos] = Ssk[i];
        pos += 1;
    }
}

void load_pkfile(char *filename, struct rsa_ctx *ctx, struct rsa_ctx *Sctx) {
    ctx->pk = BN_new();
    ctx->n = BN_new();
    Sctx->pk = BN_new();
    Sctx->n = BN_new();
    int pksize = 4;
    int nsize = 3;
    int Spksize = 4;
    int Snsize = 3;
    unsigned char *pknum[pksize];
    unsigned char *nnum[nsize];
    unsigned char *Spknum[pksize];
    unsigned char *Snnum[nsize];
    FILE *keyfile;
    keyfile = fopen(filename, "rb");
    fread(pknum, 1, pksize, keyfile);
    int pkn = atoi(pknum);
    unsigned char pk[pkn];
    fread(pk, 1, pkn, keyfile);
    fread(nnum, 1, nsize, keyfile);
    int nn = atoi(nnum);
    unsigned char n[nn];
    fread(n, 1, nn, keyfile);

    fread(Spknum, 1, Spksize, keyfile);
    int Spkn = atoi(Spknum);
    unsigned char Spk[Spkn];
    fread(Spk, 1, Spkn, keyfile);
    fread(Snnum, 1, Snsize, keyfile);
    int Snn = atoi(Snnum);
    unsigned char Sn[Snn];
    fread(Sn, 1, Snn, keyfile);

    fclose(keyfile);
    BN_bin2bn(pk, pkn, ctx->pk);
    BN_bin2bn(n, nn, ctx->n);
    BN_bin2bn(Spk, Spkn, Sctx->pk);
    BN_bin2bn(Sn, Snn, Sctx->n);
}

void load_skfile(char *filename, struct rsa_ctx * ctx, struct rsa_ctx *Sctx) {
    ctx->sk = BN_new();
    Sctx->sk = BN_new();
    int sksize = 4;
    int Ssksize = 4;
    unsigned char sknum[sksize];
    unsigned char Ssknum[Ssksize];
    FILE *keyfile;
    keyfile = fopen(filename, "rb");
    fread(sknum, 1, sksize, keyfile);
    int skn = atoi(sknum);
    unsigned char sk[skn];
    fread(sk, 1, skn, keyfile);

    fread(Ssknum, 1, Ssksize, keyfile);
    int Sskn = atoi(Ssknum);
    unsigned char Ssk[Sskn];
    fread(Ssk, 1, Sskn, keyfile);

    fclose(keyfile);
    BN_bin2bn(sk, skn, ctx->sk);
    BN_bin2bn(Ssk, Sskn, Sctx->sk);
}

void mypad_encrypt(unsigned char * msg, int msglen, unsigned char * X, int mask_bytes, unsigned char *nonce) {
    unsigned char tmp[mask_bytes];
    memcpy(tmp, msg, msglen);
    for (int i = 0; i < mask_bytes; i++) {
        X[i] = tmp[i] ^ nonce[i];
    }
}

void mypad_decrypt(unsigned char * msg, unsigned char * X, int mask_bytes, unsigned char *nonce) {
    for (int i = 0; i < mask_bytes; i++) {
        msg[i] = X[i] ^ nonce[i];
    }
}

int keygen(struct rsa_ctx *ctx, int psize) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_CTX_start(bnctx);
    int randstat = 0;
    int good = 1;
    /* Initialize the struct */
    ctx->sk = BN_new();
    ctx->pk = BN_new();
    ctx->n = BN_new();
    /* Initialize all bignum variables */
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *t;
    BIGNUM *tmp0;
    BIGNUM *tmp1;
    BIGNUM *ptxt;
    BIGNUM *ctxt;
    BIGNUM *z1;
    p = BN_new();
    q = BN_new();
    t = BN_new();
    tmp0 = BN_new();
    tmp1 = BN_new();
    ctxt = BN_new();
    ptxt = BN_new();
    z1 = BN_new();
    /* Set Z1 to equal 1 */
    BN_one(z1);
    /* Generate primes */

    while ((good != 0)) {
        good = 1;
        while (randstat != 1) {
            unsigned seed[524288];
            FILE *randfile;
            randfile = fopen("/dev/urandom", "rb");
            fread(seed, 1, 524288, randfile);
            fclose(randfile);

            RAND_seed(seed, 524288);
            randstat = RAND_status();
        }

        int p_result = BN_generate_prime_ex2(p, psize, 0, NULL, NULL, NULL, bnctx);
        int q_result = BN_generate_prime_ex2(q, psize, 0, NULL, NULL, NULL, bnctx);
        /* Generate the modulus */
        BN_mul(ctx->n, p, q, bnctx);
        /* Build the totient */
        BN_sub(tmp0, p, z1);
        BN_sub(tmp1, q, z1);
        BN_mul(t, tmp0, tmp1, bnctx);
        /* Generate the public key */
        BN_rand_range(ctx->pk, t);
        BN_gcd(tmp0, ctx->pk, t, bnctx);
        while ((BN_cmp(tmp0, z1) != 0)) {
            BN_rand_range(ctx->pk, t);
            BN_gcd(tmp0, ctx->pk, t, bnctx);
        }
        /* Generate the private key */
        BN_mod_inverse(ctx->sk, ctx->pk, t, bnctx);

        BN_set_word(tmp0, 123);
        rsa_encrypt(ctx, ctxt, tmp0);
        rsa_decrypt(ctx, ptxt, ctxt);

        if (BN_cmp(ptxt, tmp0) == 0) {
            good = 0;
        }
}

    BN_free(p);
    BN_free(q);
    BN_free(t);
    BN_free(tmp0);
    BN_free(tmp1);
    BN_free(ctxt);
    BN_free(ptxt);
    BN_free(z1);
    return good;
}
