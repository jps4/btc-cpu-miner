
#ifndef MINING_API_H
#define MINING_API_H

#include <string.h>
#include <iostream>
#include "version.h"

// Mining
#define MAX_NONCE_STEP    5000000U
#define MAX_NONCE       225000000U
#define TARGET_NONCE    471136297U
#define DEFAULT_DIFFICULTY  0.0016  // 5-zero hash
#define KEEPALIVE_TIME_ms       30000
#define POOLINACTIVITY_TIME_ms  60000

#define NUM_MAX_NONCE   4294967295
#define INIT_NUM_MAX_ONCE 4284967295

#define TARGET_BUFFER_SIZE 64

void runStratumWorker(void *name);
void runMonitorStats(void *name);
void runMiner(uint32_t task_id);
std::string printLocalTime(void);

typedef struct{
  uint8_t bytearray_target[32];
  uint8_t bytearray_pooltarget[32];
  uint8_t merkle_result[32];
  uint8_t bytearray_blockheader[80];
  // uint8_t bytearray_blockheader2[80];
  double poolDifficulty;
  bool inRun;
  bool newJob[MAX_MINING_THREADS];
  uint32_t nInitNonce;
}miner_data;

static miner_data mMiner; //Global miner data (Create a miner class TODO)

#endif // UTILS_API_H