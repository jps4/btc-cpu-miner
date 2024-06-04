#include <thread>
#include <chrono>
#include <time.h>
#include <iomanip>
#include <cstdint>
#include <csignal>

#include <unistd.h>
#include <termios.h>

#include "sha/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "SimpleJsonRpcClient.h"
#include "drivers/storage/storage.h"

uint32_t templates = 0;
uint32_t hashes = 0;
uint32_t Mhashes = 0;
uint32_t totalKHashes = 0;
// uint32_t elapsedKHs = 0;
uint64_t upTime = 0;

uint32_t shares; // increase if blockhash has 32 bits of zeroes
uint32_t valids; // increased if blockhash <= target

// Track best diff and hash
double best_diff = 0.0;
uint8_t best_hash[32];

void printHash(double diff_hash, uint8_t hash[32]){
  char best_diff_string[16] = {0};
  suffix_string(diff_hash, best_diff_string, 16, 0);

  std::cout << "Best diff: " << best_diff_string << std::endl;
  std::cout << "Best share: ";
  for (size_t i = 0; i < 32; i++)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  std::cout << std::endl;
}

// Variables to hold data from custom textboxes
//Track mining stats in non volatile memory
extern TSettings Settings;
extern volatile sig_atomic_t sigint_received;
extern int mining_threads;

//Global work data 
static SimpleJsonRpcClient client;
//miner_data mMiner; //Global miner data (Create a miner class TODO)
mining_subscribe mWorker;
mining_job mJob;
// monitor_data mMonitor;
bool isMinerSuscribed = false;
unsigned long mLastTXtoPool = millis();

int saveIntervals[7] = {5 * 60, 15 * 60, 30 * 60, 1 * 360, 3 * 360, 6 * 360, 12 * 360};
int saveIntervalsSize = sizeof(saveIntervals)/sizeof(saveIntervals[0]);
int currentIntervalIndex = 0;


std::string getHashRate(double elapsedHs, uint32_t secElapsed)
{
    char hasrate_string[32] = {0};
    suffix_string(elapsedHs / secElapsed, hasrate_string, 32, 2);
    return std::string(hasrate_string);
}
std::string getHashAmount(double nHashes)
{
    char hashes_string[32] = {0};
    suffix_string(nHashes, hashes_string, 32, 2);
    return std::string(hashes_string);
}


void runMonitorStats(void *name) {
    double totalHashes = 0;
    uint32_t mLastCheck = 0;

    while(!sigint_received) {
        struct termios old_t, new_t;
        tcgetattr(STDIN_FILENO, &old_t);
        new_t = old_t;
        new_t.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

        char ch;
        std::cin.get(ch);

        tcsetattr(STDIN_FILENO, TCSANOW, &old_t);

        uint32_t mElapsed = millis() - mLastCheck;
        while (mElapsed < 1000){
          sleep(200);
          mElapsed = millis() - mLastCheck;
        }
        mLastCheck = millis();

        double currentKHashes = (Mhashes * 1000.0) + (hashes/1000.0);
        uint32_t elapsedHs = 1000 * (currentKHashes - (totalHashes/1000));
        totalHashes = 1000*currentKHashes;

        std::cout << std::endl << "Up time: " << std::dec << format_duration(mLastCheck/1000) << std::endl;
        std::cout << "Blocks handled: " << templates << std::endl;
        // std::cout << "Total Mhashes and hashes: " << Mhashes << "MH, " << hashes << "H" << std::endl;
        std::cout << "Total hashes: " << getHashAmount(totalHashes) << "H" << std::endl;
        std::cout << "Average hashrate: " <<  getHashRate(totalHashes, mLastCheck/1000) << "Hs" << std::endl;
        std::cout << "Current hashrate: " << getHashRate(elapsedHs, mElapsed/1000) << "Hs" << std::endl;
        std::cout << "Current pool difficulty: " << mMiner.poolDifficulty << std::endl;

        printHash(best_diff, best_hash);
        
        std::cout << "32bit shares: " << std::dec << shares << std::endl;
        std::cout << "valid blocks: " << valids << std::endl;
    }
};



bool checkPoolConnection(void) {
  
  if (client.connected()) {
    return true;
  }
  
  isMinerSuscribed = false;

  #ifdef VERBOSE
  std::cout <<  "Client not connected, trying to connect..." << std::endl;
  #endif

  //Try connecting pool IP
  if (!client.connect(Settings.PoolAddress, Settings.PoolPort)) {
    std::cerr << "Imposible to connect to : " + Settings.PoolAddress << std::endl;
    return false;
  }

  return true;
}

//Implements a socketKeepAlive function and 
//checks if pool is not sending any data to reconnect again.
//Even connection could be alive, pool could stop sending new job NOTIFY
unsigned long mStart0Hashrate = 0;
bool checkPoolInactivity(unsigned int keepAliveTime, unsigned long inactivityTime){ 

    unsigned long currentKHashes = (Mhashes*1000) + hashes/1000;
    unsigned long elapsedKHs = currentKHashes - totalKHashes; 

    // If no shares sent to pool
    // send something to pool to hold socket oppened
    if(millis() - mLastTXtoPool > keepAliveTime){
      mLastTXtoPool = millis();
      #ifdef VERBOSE
      std::cout << "Sending: KeepAlive suggest_difficulty" << std::endl;
      #endif
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
    }

    if(elapsedKHs == 0){
      //Check if hashrate is 0 during inactivityTIme
      if(mStart0Hashrate == 0) mStart0Hashrate  = millis(); 
      if((millis()-mStart0Hashrate) > inactivityTime) { mStart0Hashrate=0; return true;}
      return false;
    }

  mStart0Hashrate = 0;
  return false;
}

void runStratumWorker(void *name) {

// TEST: https://bitcoin.stackexchange.com/questions/22929/full-example-data-for-scrypt-stratum-client

  // connect to pool
  
  double currentPoolDifficulty = DEFAULT_DIFFICULTY;

  while(!sigint_received) {
      
    while(!checkPoolConnection()){
      sleep(5000);
    }

    if(!isMinerSuscribed){

      //Stop miner current jobs
      mMiner.inRun = false;
      mWorker = init_mining_subscribe();

      // STEP 1: Pool server connection (SUBSCRIBE)
      if(!tx_mining_subscribe(client, mWorker)) { 
        client.stop();
        continue; 
      }
      
      strcpy(mWorker.wName, Settings.BtcWallet);
      strcpy(mWorker.wPass, Settings.PoolPassword);
      // STEP 2: Pool authorize work (Block Info)
      tx_mining_auth(client, mWorker.wName, mWorker.wPass); //Don't verifies authoritzation, TODO

      // STEP 3: Suggest pool difficulty
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);

      isMinerSuscribed=true;
      mLastTXtoPool = millis();
    }

    //Check if pool is down for almost 5minutes and then restart connection with pool (1min=600000ms)
    if(checkPoolInactivity(KEEPALIVE_TIME_ms, POOLINACTIVITY_TIME_ms)){
      //Restart connection
      std::cerr << "  Detected more than 2 min without data form stratum server. Closing socket and reopening..." << std::endl;
      client.stop();
      isMinerSuscribed=false;
      continue; 
    }

    //Read pending messages from pool
    miner_data newMiner;
    while(!sigint_received && client.connected()){

      std::string line = client.readStringUntil('\n');
      stratum_method result = parse_mining_method(line);
      switch (result)
      {
          case STRATUM_PARSE_ERROR:   std::cerr << "  Parsed JSON: error on JSON:" << line << std::endl; break;
          case ERROR_DIFFICULTY_TOO_LOW:
              tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
              break;
          case ERROR_JOB_NOT_FOUND:
              //Stop miner current jobs
              newMiner.inRun = false;
              for (int i=0; i< mining_threads; i++)
                newMiner.newJob[i] = true;
              break;
          case MINING_NOTIFY:         if(parse_mining_notify(line, mJob)){
                                          //Increse templates readed
                                          templates++;
                                          //Prepare data for new jobs
                                          newMiner = calculateMiningData(mWorker,mJob);
                                          newMiner.poolDifficulty = currentPoolDifficulty;

                                          //Stop miner current jobs
                                          newMiner.inRun = false;
                                          for (int i=0; i< mining_threads; i++)
                                            newMiner.newJob[i] = true;
                                          //Give new job to miner
                                          mMiner = newMiner;
                                          
                                          #ifdef VERBOSE
                                          printHash(best_diff, best_hash);
                                          #endif
                                      }
                                      break;
          case MINING_SET_DIFFICULTY: parse_mining_set_difficulty(client, line, currentPoolDifficulty);
                                      mMiner.poolDifficulty = currentPoolDifficulty;
                                      #ifdef VERBOSE
                                      std::cout << "  Pool difficulty changed to " << currentPoolDifficulty << std::endl;
                                      #endif
                                      break;
          case STRATUM_SUCCESS:       break;
          default:                    std::cerr << "  Parsed JSON: unknown" << std::endl; break;

      }
    }
   
  }
  
}


//////////////////THREAD CALLS///////////////////

//This works only with one thread, TODO -> Class or miner_data for each thread


  
void runMiner(uint32_t task_id) {

  // uint32_t miner_id = reinterpret_cast<uintptr_t>(task_id);
  uint32_t miner_id = task_id;

  #ifdef VERBOSE
  std::cout << "[MINER] " << miner_id << ": Started runMiner Task!"  << std::endl;
  #endif

  while(!sigint_received){

    //Wait new job
    while(!sigint_received){
      if (mMiner.newJob[miner_id] == true)
        break;

      sleep(100);
    }

    if(mMiner.newJob[miner_id])
      mMiner.newJob[miner_id] = false; //Clear newJob flag

    mMiner.inRun = true; //Set inRun flag

    // mMonitor.NerdStatus = NM_hashing;

    uint8_t bytearray_blockheader_copy[80];
    memcpy(bytearray_blockheader_copy, mMiner.bytearray_blockheader, 80);

    //Prepare Premining data
    nerdSHA256_context nerdMidstate; //NerdShaplus
    uint8_t hash[32];
    uint8_t hash_new[32];

    //Calcular midstate
    nerd_mids(&nerdMidstate, bytearray_blockheader_copy); //NerdShaplus

    // search a valid nonce
    //uint32_t nonce = TARGET_NONCE - MAX_NONCE;
    uint32_t nonce = mMiner.nInitNonce;
    
    // split up odd/even nonces between miner tasks
    nonce += miner_id;
    uint8_t *header64;

    header64 = bytearray_blockheader_copy + 64;
    
    bool bValidToSend = true;
    bool bShow = false;

    #ifdef VERBOSE
    std::cout << "[MINER] " << miner_id << ": STARTING TO HASH NONCES" << std::endl;
    #endif

    while(!sigint_received) {
      if(!mMiner.inRun) {
        #ifdef VERBOSE
        std::cout << "MINER " << miner_id << " WORK ABORTED >> waiting new job" << std::endl;
        #endif
        break;
      }

      // if (nonce > TARGET_NONCE) break; //exit
      if (nonce > NUM_MAX_NONCE)
        break;

      memcpy(bytearray_blockheader_copy + 76, &nonce, 1*sizeof(uint32_t));
      // bValidToSend = nerd_sha256d(&nerdMidstate, header64, mMiner.poolDifficulty, hash);
      bValidToSend = nerd_sha256d(&nerdMidstate, header64, mMiner.poolDifficulty, hash);

      hashes++;
      if(!mMiner.inRun) {
        #ifdef VERBOSE
        std::cout << "MINER " << miner_id << " WORK ABORTED >> waiting new job" << std::endl;
        #endif
        break;
      }

      if(!bValidToSend) {
        nonce += mining_threads;
        continue;
      }

      // TESTS FOR OPTIMIZATION
      // bool bValidToSend2 = nerd_sha256d_new(&nerdMidstate, header64, mMiner.poolDifficulty, hash_new);

      // std::cout << "   - HASH NEW: ";
      // for (size_t i = 0; i < 32; i++)
      //   std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash_new[i]);
      // std::cout << "" << std::endl;

      // std::cout << "   - HASH OLD: ";
      // for (size_t i = 0; i < 32; i++)
      //   std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
      // std::cout << "" << std::endl;

      // if(!bValidToSend2) {
      //   std::cout << "EEEERRRRRROOOORRRR!!!!!!!" << std::endl;
      //   nonce += mining_threads;
      //   continue;
      // }


      //Check target to submit
      //Difficulty of 1 > 0x00000000FFFF0000000000000000000000000000000000000000000000000000
      //NM2 pool diff 1e-9 > Target = diff_1 / diff_pool > 0x00003B9ACA00....00
      //Swapping diff bytes little endian >>>>>>>>>>>>>>>> 0x0000DC59D300....00  
      //if((hash[29] <= 0xDC) && (hash[28] <= 0x59))     //0x00003B9ACA00  > diff value for 1e-9
      double diff_hash = diff_from_target(hash);

      // update best diff
      if (diff_hash > best_diff){
        best_diff = diff_hash;
        memcpy(best_hash, hash, 32);
        bShow = true;
      }

      if(diff_hash > mMiner.poolDifficulty)//(hash[29] <= 0x3B)//(diff_hash > 1e-9)
      {
        tx_mining_submit(client, mWorker, mJob, nonce);

        #ifdef VERBOSE
        std::cout << "   - Current diff share: " << diff_hash << std::endl;
        std::cout << "   - Current pool diff : " << mMiner.poolDifficulty << std::endl;
        std::cout << "   - TX SHARE: ";
        for (size_t i = 0; i < 32; i++)
          std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        std::cout << "" << std::endl;
        std::cout <<"   - Current nonce: " << nonce << std::endl;
        #endif

        #ifdef DEBUG_MINING
        std::cout <<"   - Current nonce: " << nonce << std::endl;
        std::cout <<"   - Current block header: ";
        for (size_t i = 0; i < 80; i++) {
          std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytearray_blockheader_copy[i]);
        }
        std::cout << "" << std::endl;
        #endif

        mLastTXtoPool = millis();  
      }
      
      if (bShow){
        bShow = false;
        #ifdef VERBOSE
        printHash(best_diff, best_hash);
        #endif
      }

      // check if 32bit share
      if(hash[28] !=0 || hash[29] != 0) {
        // increment nonce
        nonce += mining_threads;
        continue;
      }
      shares++;

      // check if valid header
      if(checkValid(hash, mMiner.bytearray_target)){
        std::cout << "[WORKER] " << miner_id << ": CONGRATULATIONS! Valid block found with nonce: " << nonce << std::endl;
        valids++;
        std::cout << "[WORKER] " << miner_id << ":  Submitted work valid!" << std::endl;
        // wait for new job
        break;
      }
      // increment nonce
      nonce += mining_threads;
    } // exit if found a valid result or nonce > MAX_NONCE

    mMiner.inRun = false;

    #ifdef VERBOSE
    std::cout << "[WORKER] " << miner_id << ": Finished job waiting new data from pool" << std::endl;
    #endif

    while(hashes>=MAX_NONCE_STEP) {
      Mhashes += (MAX_NONCE_STEP/1000000);
      hashes -= MAX_NONCE_STEP;
    }
  }
}

