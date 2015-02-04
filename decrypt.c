#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

struct CCZHeader {
    unsigned char   sig[4];             // signature. Should be 'CCZ!' 4 bytes
    unsigned short  compression_type;   // should 0
    unsigned short  version;            // should be 2 (although version type==1 is also supported)
    unsigned int    reserved;           // Reserved for users.
    unsigned int    len;                // size of the uncompressed file
};

unsigned char* getFileData(const char* pszFileName, const char* pszMode, unsigned long * pSize)
{
    unsigned char * pBuffer = NULL;
    if (pszFileName == NULL || pSize == NULL || pszMode == NULL) {
        printf("Invalid parameters.\n");
        return NULL;
    }

    *pSize = 0;
    do
    {
        // read the file from hardware
        FILE *fp = fopen(pszFileName, pszMode);
        if (!fp) {
            break;
        }

        fseek(fp,0,SEEK_END);
        *pSize = ftell(fp);
        fseek(fp,0,SEEK_SET);
        pBuffer = (unsigned char*)malloc(*pSize);
        *pSize = fread(pBuffer,sizeof(unsigned char), *pSize,fp);
        fclose(fp);
    } while (0);

    if (! pBuffer)
    {
        printf("Get data from file %s failed\n", pszFileName);
    }
    return pBuffer;
}

unsigned int s_uEncryptedPvrKeyParts[4] = {0x23956313, 0x4a24b40b, 0x0c6e67cc, 0xd83ad589};
unsigned int s_uEncryptionKey[1024];
s_bEncryptionKeyIsValid = 0;

void ccDecodeEncodedPvr(unsigned int *data, int len)
{
    const int enclen = 1024;
    const int securelen = 512;
    const int distance = 64;

    // create long key
    if(!s_bEncryptionKeyIsValid)
    {
        unsigned int y, p, e;
        unsigned int rounds = 6;
        unsigned int sum = 0;
        unsigned int z = s_uEncryptionKey[enclen-1];

        do
        {
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (s_uEncryptedPvrKeyParts[(p&3)^e] ^ z)))

            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < enclen - 1; p++)
            {
                y = s_uEncryptionKey[p + 1];
                z = s_uEncryptionKey[p] += MX;
            }

            y = s_uEncryptionKey[0];
            z = s_uEncryptionKey[enclen - 1] += MX;

        } while (--rounds);

        s_bEncryptionKeyIsValid = 1;
    }

    int b = 0;
    int i = 0;

    // encrypt first part completely
    for(; i < len && i < securelen; i++)
    {
        data[i] ^= s_uEncryptionKey[b++];

        if(b >= enclen)
        {
            b = 0;
        }
    }

    // encrypt second section partially
    for(; i < len; i += distance)
    {
        data[i] ^= s_uEncryptionKey[b++];

        if(b >= enclen)
        {
            b = 0;
        }
    }
}

void decryptFile(unsigned char* filename) {
    unsigned long fileLen = 0;
    unsigned char *compressed = getFileData(filename, "rb", &fileLen);

    if(NULL == compressed || 0 == fileLen) {
        printf("Error loading CCZ compressed file\n");
        return;
    }

    struct CCZHeader *header = (struct CCZHeader*) compressed;
    header->sig[3] = '!';

    // decrypt
    unsigned int* ints = (unsigned int*)(compressed+12);
    int enclen = (fileLen-12)/4;
    ccDecodeEncodedPvr(ints, enclen);


    FILE *fpw = fopen(filename, "wb");
    if(!fpw) {
        printf("open write file failed\n");
        return;
    }

    size_t writeSize = fwrite(compressed, 1, fileLen, fpw);
    printf("write %d bytes to file %s\n", writeSize, filename);

    fclose(fpw);
}

int main(int argc, const char *argv[])
{
    const char* name = argv[1];

    DIR *dp = opendir(".");
    struct dirent *dirp;
    while((dirp = readdir(dp)) != NULL) {
        printf("dirent: %s\n", dirp->d_name);
        if(strstr(dirp->d_name, ".pvr.ccz") != NULL) {
            decryptFile(dirp->d_name);
        }
    }
    return 0;
}
