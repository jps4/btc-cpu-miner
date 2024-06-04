#ifndef STRATUM_API_H
#define STRATUM_API_H

#include <cstdint>
#include <iostream>
#include <vector>

#include "include/rapidjson/document.h"
#include "SimpleJsonRpcClient.h"

#define MAX_MERKLE_BRANCHES 32
#define HASH_SIZE 32
#define COINBASE_SIZE 100
#define COINBASE2_SIZE 128

#define BUFFER_JSON_DOC 4096
#define BUFFER 1024

typedef struct {
    std::string sub_details;
    std::string extranonce1;
    std::string extranonce2;
    int extranonce2_size;
    char wName[80];
    char wPass[20];
} mining_subscribe;

typedef struct {


    std::string job_id;
    std::string prev_block_hash;
    std::string coinb1;
    std::string coinb2;
    std::string nbits;
    std::vector<std::string> merkle_branch;
    std::string version;
    unsigned int target;
    std::string ntime;
    bool clean_jobs;
} mining_job;

typedef enum {
    STRATUM_SUCCESS,
    STRATUM_UNKNOWN,
    STRATUM_PARSE_ERROR,
    MINING_NOTIFY,
    MINING_SET_DIFFICULTY,
    ERROR_DIFFICULTY_TOO_LOW,
    ERROR_JOB_NOT_FOUND
} stratum_method;

unsigned long getNextId(unsigned long id);
bool verifyPayload (std::string& line);
bool checkError(const rapidjson::Document& doc);

//Method Mining.subscribe
mining_subscribe init_mining_subscribe(void);
bool tx_mining_subscribe(SimpleJsonRpcClient& client, mining_subscribe& mSubscribe);
bool parse_mining_subscribe(std::string& line, mining_subscribe& mSubscribe);

//Method Mining.authorise
bool tx_mining_auth(SimpleJsonRpcClient& client, const char * user, const char * pass);
stratum_method parse_mining_method(std::string& line);
bool parse_mining_notify(std::string& line, mining_job& mJob);

//Method Mining.submit
bool tx_mining_submit(SimpleJsonRpcClient& client, mining_subscribe& mWorker, mining_job& mJob, unsigned long nonce);

//Difficulty Methods 
bool tx_suggest_difficulty(SimpleJsonRpcClient& client, double difficulty);
bool parse_mining_set_difficulty(SimpleJsonRpcClient& client, std::string& line, double& difficulty);


#endif // STRATUM_API_H