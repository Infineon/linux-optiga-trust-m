#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "trustm_helper.h"

int main (int argc, char **argv)
{
	uint16_t err;

	err = 1;
	trustmPrintErrorCode(err);	
	for(err=0x0102; err<=0x0108;err++)
		trustmPrintErrorCode(err);

	for(err=0x0202; err<=0x0204;err++)
		trustmPrintErrorCode(err);

	for(err=0x0302; err<=0x0305;err++)
		trustmPrintErrorCode(err);

	for(err=0x0402; err<=0x0405;err++)
		trustmPrintErrorCode(err);

	for(err=0x8001; err<=0x8010;err++)
		trustmPrintErrorCode(err);

	for(err=0x8021; err<=0x8024;err++)
		trustmPrintErrorCode(err);
		
	for(err=0x8026; err<=0x802E;err++)
		trustmPrintErrorCode(err);		
	return 0;
}
