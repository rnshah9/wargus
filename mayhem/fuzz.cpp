#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

#include "pud.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    unsigned char* buf = (unsigned char*) malloc(sizeof(unsigned char) * 100);
    provider.ConsumeData(buf, sizeof(unsigned char) * 100);

    PudData pd;
    pd.Parse(buf, sizeof(unsigned char) * 100);

    free(buf);
    return 0;
}
