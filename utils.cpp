
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <iomanip>
#include <random>

#include "mining.h"
#include "stratum.h"
// #include "include/mbedtls/sha256.h"
#include "sha/sha.h"

extern int mining_threads;

int millis(){
  return clock() * 1000 / CLOCKS_PER_SEC;
}

void sleep(int ms){
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

#ifndef bswap_16
#define bswap_16(a) ((((uint16_t) (a) << 8) & 0xff00) | (((uint16_t) (a) >> 8) & 0xff))
#endif

#ifndef bswap_32
#define bswap_32(a) ((((uint32_t) (a) << 24) & 0xff000000) | \
		     (((uint32_t) (a) << 8) & 0xff0000) | \
     		     (((uint32_t) (a) >> 8) & 0xff00) | \
     		     (((uint32_t) (a) >> 24) & 0xff))
#endif

uint32_t swab32(uint32_t v) {
    return bswap_32(v);
}

uint8_t hex(char ch) {
    uint8_t r = (ch > 57) ? (ch - 55) : (ch - 48);
    return r & 0x0F;
}

int to_byte_array(const char *in, size_t in_size, uint8_t *out) {
    int count = 0;
    if (in_size % 2) {
        while (*in && out) {
            *out = hex(*in++);
            if (!*in)
                return count;
            *out = (*out << 4) | hex(*in++);
            *out++;
            count++;
        }
        return count;
    } else {
        while (*in && out) {
            *out++ = (hex(*in++) << 4) | hex(*in++);
            count++;
        }
        return count;
    }
}

void swap_endian_words(const char * hex_words, uint8_t * output) {
    size_t hex_length = strlen(hex_words);
    if (hex_length % 8 != 0) {
        fprintf(stderr, "Must be 4-byte word aligned\n");
        exit(EXIT_FAILURE);
    }

    size_t binary_length = hex_length / 2;

    for (size_t i = 0; i < binary_length; i += 4) {
        for (int j = 0; j < 4; j++) {
            unsigned int byte_val;
            sscanf(hex_words + (i + j) * 2, "%2x", &byte_val);
            output[i + (3 - j)] = byte_val;
        }
    }
}

void reverse_bytes(uint8_t * data, size_t len) {
    for (int i = 0; i < len / 2; ++i) {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
/* Converts a little endian 256 bit value to a double */
double le256todouble(uint8_t *target)
{
	uint64_t *data64;
	double dcut64;

	// data64 = (uint64_t *)(target + 24);
    data64 = reinterpret_cast<uint64_t*>(target + 24);
	dcut64 = *data64 * 6277101735386680763835789423207666416102355444464034512896.0;

	// data64 = (uint64_t *)(target + 16);
    data64 = reinterpret_cast<uint64_t*>(target + 16);
	dcut64 += *data64 * 340282366920938463463374607431768211456.0;

	// data64 = (uint64_t *)(target + 8);
    data64 = reinterpret_cast<uint64_t*>(target + 8);
	dcut64 += *data64 * 18446744073709551616.0;

	// data64 = (uint64_t *)(target);
    data64 = reinterpret_cast<uint64_t*>(target);
	dcut64 += *data64;

	return dcut64;
}

double diff_from_target(uint8_t *target)
{
	double d64, dcut64;

	d64 = truediffone;
	dcut64 = le256todouble(target);
	if (!dcut64)
		dcut64 = 1;
	return d64 / dcut64;
}

/****************** PREMINING CALCULATIONS ********************/


bool checkValid(unsigned char* hash, unsigned char* target) {
  bool valid = true;
  unsigned char diff_target[32];
  memcpy(diff_target, &target, 32);
  //convert target to little endian for comparison
  reverse_bytes(diff_target, 32);

  for(uint8_t i=31; i>=0; i--) {
    if(hash[i] > diff_target[i]) {
      valid = false;
      break;
    }
  }

  #ifdef DEBUG_MINING
  if (valid) {
    std::cout << "\tvalid : ";
    for (size_t i = 0; i < 32; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    std::cout << std::endl;
  }
  #endif
  return valid;
}

std::string getNextExtranonce2(int extranonce2_size, std::string& extranonce2) {
    unsigned long extranonce2_number = strtoul(extranonce2.c_str(), NULL, 10);
    extranonce2_number++;

    char ret[2 * extranonce2_size + 1];
    if (extranonce2_number > long(pow(10, 2 * extranonce2_size))) {
        extranonce2_number = 0;
    }
    snprintf(ret, 2 * extranonce2_size + 1, "%0*lu", 2 * extranonce2_size, extranonce2_number);
    return std::string(ret);
}

miner_data init_miner_data(void){
  
  miner_data newMinerData;

  newMinerData.poolDifficulty = DEFAULT_DIFFICULTY;
  newMinerData.inRun = false;
  for ( int i =0; i < mining_threads; i++)
    newMinerData.newJob[i] = false;
  
  return newMinerData;
}

uint32_t generateRandomNumber(uint32_t min, uint32_t max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(min, max);
    return dis(gen);
}


miner_data calculateMiningData(mining_subscribe& mWorker, mining_job mJob){

  miner_data mRetMiner = init_miner_data();

    mRetMiner.nInitNonce = generateRandomNumber(0, INIT_NUM_MAX_ONCE);

  // calculate target - target = (nbits[2:]+'00'*(int(nbits[:2],16) - 3)).zfill(64)
    
    char target[TARGET_BUFFER_SIZE+1];
    memset(target, '0', TARGET_BUFFER_SIZE);
    int zeros = (int) strtol(mJob.nbits.substr(0, 2).c_str(), 0, 16) - 3;
    memcpy(target + zeros - 2, mJob.nbits.substr(2).c_str(), mJob.nbits.length() - 2);
    target[TARGET_BUFFER_SIZE] = 0;
    #ifdef VERBOSE
    std::cout << "    target: " << target << std::endl;
    #endif
    
    // bytearray target
    size_t size_target = to_byte_array(target, 32, mRetMiner.bytearray_target);

    for (size_t j = 0; j < 8; j++) {
      mRetMiner.bytearray_target[j] ^= mRetMiner.bytearray_target[size_target - 1 - j];
      mRetMiner.bytearray_target[size_target - 1 - j] ^= mRetMiner.bytearray_target[j];
      mRetMiner.bytearray_target[j] ^= mRetMiner.bytearray_target[size_target - 1 - j];
    }

    // get extranonce2 - extranonce2 = hex(random.randint(0,2**32-1))[2:].zfill(2*extranonce2_size)
    //To review
    mWorker.extranonce2 = getNextExtranonce2(mWorker.extranonce2_size, mWorker.extranonce2);
    //mWorker.extranonce2 = "00000002";
    
    //get coinbase - coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()
    std::string coinbase = mJob.coinb1 + mWorker.extranonce1 + mWorker.extranonce2 + mJob.coinb2;
    #ifdef VERBOSE
    std::cout << "    coinbase: " << coinbase << std::endl;
    #endif

    size_t str_len = coinbase.length()/2;
    uint8_t bytearray[str_len];

    size_t res = to_byte_array(coinbase.c_str(), str_len*2, bytearray);

    #ifdef DEBUG_MINING
    std::cout << "    extranonce2: " << mWorker.extranonce2 << std::endl;
    std::cout << "    coinbase: " << coinbase << std::endl;
    std::cout << "    coinbase bytes - size: " << res << std::endl;

    for (size_t i = 0; i < res; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytearray[i]);
    std::cout <<  "---" << std::endl;
    #endif

    sha256_ctx ctx;
    uint8_t shaResult[32];
    sha256_init(&ctx);
    sha256d(bytearray, str_len, shaResult);

    #ifdef DEBUG_MINING
    std::cout << "    coinbase double sha: " << std::endl;
    for (size_t i = 0; i < 32; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(shaResult[i]);
    std::cout << std::endl;
    #endif

    
    // copy coinbase hash
    memcpy(mRetMiner.merkle_result, shaResult, sizeof(shaResult));
    
    uint8_t merkle_concatenated[32 * 2];
    for (size_t k=0; k < mJob.merkle_branch.size(); k++) {
        const char* merkle_element = mJob.merkle_branch[k].c_str();
        uint8_t bytearray[32];
        size_t res = to_byte_array(merkle_element, 64, bytearray);

        #ifdef DEBUG_MINING
        std::cout <<  "    merkle element    " << k << ": " << merkle_element << std::endl;
        #endif
        for (size_t i = 0; i < 32; i++) {
          merkle_concatenated[i] = mRetMiner.merkle_result[i];
          merkle_concatenated[32 + i] = bytearray[i];
        }

        #ifdef DEBUG_MINING
        std::cout <<  "    merkle element    " << k << ": " << merkle_element << std::endl;
        std::cout <<  "    merkle concatenated: ";
        for (size_t i = 0; i < 64; i++)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(merkle_concatenated[i]);
        std::cout << std::endl;
        #endif

        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256d(merkle_concatenated, 64, mRetMiner.merkle_result);

        // mbedtls_sha256_context ctx;
        // mbedtls_sha256_init(&ctx);
        // mbedtls_sha256_starts_ret(&ctx,0);
        // mbedtls_sha256_update_ret(&ctx, merkle_concatenated, 64);
        // mbedtls_sha256_finish_ret(&ctx, interResult);

        // mbedtls_sha256_starts_ret(&ctx,0);
        // mbedtls_sha256_update_ret(&ctx, interResult, 32);
        // mbedtls_sha256_finish_ret(&ctx, mRetMiner.merkle_result);
        // mbedtls_sha256_free(&ctx);

        #ifdef DEBUG_MINING
        std::cout << "    merkle sha         : ";
        for (size_t i = 0; i < 32; i++)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.merkle_result[i]);
        std::cout << std::endl;
        #endif
    }
    // merkle root from merkle_result
    
    #ifdef VERBOSE
    std::cout << "    merkle sha         : ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.merkle_result[i]);
    }
    std::cout << std::endl;
    #endif

    char merkle_root[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&merkle_root[i*2], 3, "%02x", mRetMiner.merkle_result[i]);
    }

    // calculate blockheader
    // j.block_header = ''.join([j.version, j.prevhash, merkle_root, j.ntime, j.nbits])
    std::string blockheader = mJob.version + mJob.prev_block_hash + std::string(merkle_root) + mJob.ntime + mJob.nbits + "00000000";
    str_len = blockheader.length()/2;
    
    res = to_byte_array(blockheader.c_str(), str_len*2, mRetMiner.bytearray_blockheader);

    #ifdef DEBUG_MINING
    std::cout << "    blockheader: " << blockheader << std::endl;
    std::cout << "    blockheader bytes " << str_len << " -> " << std::endl;
    #endif

    // reverse version
    uint8_t buff;
    size_t bword, bsize, boffset;
    boffset = 0;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mRetMiner.bytearray_blockheader[j];
        mRetMiner.bytearray_blockheader[j] = mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }

    // reverse prev hash (4-byte word swap)
    boffset = 4;
    bword = 4;
    bsize = 32;
    for (size_t i = 1; i <= bsize / bword; i++) {
        for (size_t j = boffset; j < boffset + bword / 2; j++) {
            buff = mRetMiner.bytearray_blockheader[j];
            mRetMiner.bytearray_blockheader[j] = mRetMiner.bytearray_blockheader[2 * boffset + bword - 1 - j];
            mRetMiner.bytearray_blockheader[2 * boffset + bword - 1 - j] = buff;
        }
        boffset += bword;
    }

/*
    // reverse merkle (4-byte word swap)
    boffset = 36;
    bword = 4;
    bsize = 32;
    for (size_t i = 1; i <= bsize / bword; i++) {
        for (size_t j = boffset; j < boffset + bword / 2; j++) {
            buff = mRetMiner.bytearray_blockheader[j];
            mRetMiner.bytearray_blockheader[j] = mRetMiner.bytearray_blockheader[2 * boffset + bword - 1 - j];
            mRetMiner.bytearray_blockheader[2 * boffset + bword - 1 - j] = buff;
        }
        boffset += bword;
    }
*/
    // reverse ntime
    boffset = 68;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mRetMiner.bytearray_blockheader[j];
        mRetMiner.bytearray_blockheader[j] = mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }

    // reverse difficulty
    boffset = 72;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mRetMiner.bytearray_blockheader[j];
        mRetMiner.bytearray_blockheader[j] = mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mRetMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }


    #ifdef DEBUG_MINING
    std::cout << " >>> bytearray_blockheader     : "; 
    for (size_t i = 0; i < 4; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);
    std::cout << std::endl;
    std::cout << "version     ";
    for (size_t i = 0; i < 4; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout << "prev hash   ";
    for (size_t i = 4; i < 4+32; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout << "merkle root ";
    for (size_t i = 36; i < 36+32; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout << "ntime       ";
    for (size_t i = 68; i < 68+4; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout << "nbits       ";
    for (size_t i = 72; i < 72+4; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout << "nonce       ";
    for (size_t i = 76; i < 76+4; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);

    std::cout << std::endl;
    std::cout <<"bytearray_blockheader: ";
    for (size_t i = 0; i < str_len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mRetMiner.bytearray_blockheader[i]);
    }
    std::cout << std::endl;

    std::cout.flush();
    #endif

    return mRetMiner;
}

/* Convert a double value into a truncated string for displaying with its
 * associated suitable for Mega, Giga etc. Buf array needs to be long enough */
void suffix_string(double val, char *buf, size_t bufsiz, int sigdigits)
{
	const double kilo = 1000;
	const double mega = 1000000;
	const double giga = 1000000000;
	const double tera = 1000000000000;
	const double peta = 1000000000000000;
	const double exa  = 1000000000000000000;
	// minimum diff value to display
	const double min_diff = 0.001;

	char suffix[2] = "";
	bool decimal = true;
	double dval;

	if (val >= exa) {
		val /= peta;
		dval = val / kilo;
		strcpy(suffix, "E");
	} else if (val >= peta) {
		val /= tera;
		dval = val / kilo;
		strcpy(suffix, "P");
	} else if (val >= tera) {
		val /= giga;
		dval = val / kilo;
		strcpy(suffix, "T");
	} else if (val >= giga) {
		val /= mega;
		dval = val / kilo;
		strcpy(suffix, "G");
	} else if (val >= mega) {
		val /= kilo;
		dval = val / kilo;
		strcpy(suffix, "M");
	} else if (val >= kilo) {
		dval = val / kilo;
		strcpy(suffix, "K");
	} else {
		dval = val;
		if (dval < min_diff)
			dval = 0.0;
	}

	if (!sigdigits) {
		if (decimal)
			snprintf(buf, bufsiz, "%.3f%s", dval, suffix);
		else
			snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
	} else {
		/* Always show sigdigits + 1, padded on right with zeroes
		 * followed by suffix */
		int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

		snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
	}
}

std::string format_duration(int secElapsed) {
    char timeMining[15] = {0};

    int days = secElapsed / 86400;
    int hours = (secElapsed - (days * 86400)) / 3600;               // Number of seconds in an hour
    int mins = (secElapsed - (days * 86400) - (hours * 3600)) / 60; // Remove the number of hours and calculate the minutes.
    int secs = secElapsed - (days * 86400) - (hours * 3600) - (mins * 60);
    sprintf(timeMining, "%01dd %02d:%02d:%02d", days, hours, mins, secs);

    return std::string(timeMining);
}
