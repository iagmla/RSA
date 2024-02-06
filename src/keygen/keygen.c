#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rsa_keygen(int psize, char * prefix) {
    struct rsa_ctx ctx;
    keygen(&ctx, psize);
    printf("RSA encryption public keys generated successfully.\n");

    struct rsa_ctx Sctx;
    keygen(&Sctx, psize);
    printf("RSA signing public keys generated successfully.\n");
    pkg_pk(&ctx, &Sctx, prefix);

    char *skfilename[256];
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");

    int total = pkg_sk_bytes_count(&ctx, &Sctx);
    unsigned char *keyblob[total];
    pkg_sk_bytes(&ctx, &Sctx, keyblob);
    FILE *skfile;
    skfile = fopen(skfilename, "wb");
    fwrite(keyblob, 1, total, skfile);
    fclose(skfile);
}
