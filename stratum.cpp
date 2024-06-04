#include "stratum.h"
#include <string.h>
#include <stdio.h>
#include <iomanip>
#include <sstream>
#include <regex>

#include "utils.h"
#include "version.h"


rapidjson::Document doc;

unsigned long id = 1;
extern int mining_threads;

//Get next JSON RPC Id
unsigned long getNextId(unsigned long id) {
    if (id == ULONG_MAX) {
      id = 1;
      return id;
    }
    return ++id;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first) {
        return "";
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}


//Verify Payload doesn't has zero lenght
bool verifyPayload (std::string& line){
    trim(line);
    if(line.length() == 0) return false;
    return true;
}

bool checkError(const rapidjson::Document& doc) {
  
    if (!doc.HasMember("error")) return false;
  
    const rapidjson::Value& error = doc["error"];
    if (!error.IsArray() || error.Size() == 0) return false;

    printf("ERROR: %d | reason: %s \n", error[0].GetInt(), error[1].GetString());
    return true;
}

stratum_method returnError(const rapidjson::Document& doc) {
    if (!doc.HasMember("error")) return STRATUM_UNKNOWN;
    const rapidjson::Value& error = doc["error"];
    if (!error.IsArray() || error.Size() == 0) return STRATUM_UNKNOWN;

    std::string sError = std::string(error[1].GetString());
    if (sError == "Difficulty too low")
        return ERROR_DIFFICULTY_TOO_LOW;
    if (sError == "Job not found")
        return ERROR_JOB_NOT_FOUND;

    return STRATUM_PARSE_ERROR;
}

// STEP 1: Pool server connection (SUBSCRIBE)
    // Docs: 
    // - https://cs.braiins.com/stratum-v1/docs
    // - https://github.com/aeternity/protocol/blob/master/STRATUM.md#mining-subscribe
bool tx_mining_subscribe(SimpleJsonRpcClient& client, mining_subscribe& mSubscribe)
{
    char payload[BUFFER] = {0};
    
    // Subscribe
    id = 1; //Initialize id messages
    sprintf(payload, "{\"id\": %u, \"method\": \"mining.subscribe\", \"params\": [\"%s\"]}\n", id, NAME);
    
    #ifdef VERBOSE
    std::cout << "[WORKER] ==> Mining subscribe" << std::endl;
    std::cout << "  Sending  : " << payload << std::endl;
    #endif
    client.print(payload);
    
    sleep(100);
    
    std::string line = client.readStringUntil('\n');
    if(!parse_mining_subscribe(line, mSubscribe)) return false;

    #ifdef VERBOSE
    std::cout << "    sub_details: " << mSubscribe.sub_details << std::endl;
    std::cout << "    extranonce1: " << mSubscribe.extranonce1 << std::endl;
    std::cout << "    extranonce2_size: " << mSubscribe.extranonce2_size << std::endl;
    #endif

    if((mSubscribe.extranonce1.length() == 0) ) { 
        #ifdef VERBOSE
        std::cout << "[WORKER] >>>>>>>>> Work aborted" << std::endl;
        std::cout << "extranonce1 length: " << mSubscribe.extranonce1.length() << std::endl;
        #endif
        doc.Clear();
        return false; 
    }
    return true;
}

bool parse_mining_subscribe(std::string& line, mining_subscribe& mSubscribe)
{
    if(!verifyPayload(line)) return false;
    #ifdef VERBOSE
    std::cout << "  Receiving: " << line << std::endl;
    #endif
   
    if (doc.Parse(line.c_str()).HasParseError())
        return false;
    if (checkError(doc)) return false;
    if (!doc.HasMember("result")) return false;

    const rapidjson::Value& result = doc["result"];
    mSubscribe.sub_details = std::string(result[0][0][1].GetString());
    mSubscribe.extranonce1 = std::string(result[1].GetString());
    mSubscribe.extranonce2_size = result[2].GetInt();

    return true;
}

mining_subscribe init_mining_subscribe(void)
{
    mining_subscribe new_mSub;

    new_mSub.extranonce1 = "";
    new_mSub.extranonce2 = "";
    new_mSub.extranonce2_size = 0;
    new_mSub.sub_details = "";


    return new_mSub;
}

// STEP 2: Pool server auth (authorize)
bool tx_mining_auth(SimpleJsonRpcClient& client, const char * user, const char * pass)
{
    char payload[BUFFER] = {0};

    // Authorize
    id = getNextId(id);
    sprintf(payload, "{\"params\": [\"%s\", \"%s\"], \"id\": %u, \"method\": \"mining.authorize\"}\n", 
      user, pass, id);
    
    #ifdef VERBOSE
    std::cout << "[WORKER] ==> Autorize work" << std::endl;
    std::cout << "  Sending  : " << payload << std::endl;
    #endif
    client.print(payload);

    sleep(100);

    //Don't parse here any answer
    //Miner started to receive mining notifications so better parse all at main thread
    return true;
}

std::regex pattern("^\\{\"id\".*mining\\.notify\",\"params\"");
std::regex pattern_ok("(,\"method\":\"mining\\.notify\",\"params\")");
std::string replacement = "\\{\"id\"\\:null,\"method\":\"mining.notify\",\"params\"";

stratum_method parse_mining_method(std::string& line)
{
    if(!verifyPayload(line)) return STRATUM_PARSE_ERROR;
    #ifdef VERBOSE
    std::cout << "  Receiving: " << line << std::endl;
    #endif

    std::smatch match;
    if (std::regex_search(line, match, pattern) && !std::regex_search(line, pattern_ok)) {
        std::cout << "original: " << line << std::endl;
        line = std::regex_replace(line, pattern, replacement, std::regex_constants::format_first_only);
        std::cout << "fixed: " << line << std::endl;
    }

    if (doc.Parse(line.c_str()).HasParseError())
        return STRATUM_PARSE_ERROR;
    if (checkError(doc))
        return returnError(doc);

    if (!doc.HasMember("method")) {
      // "error":null means success
      if (!doc.HasMember("error") || doc["error"].IsNull())
        return STRATUM_SUCCESS;
      else
        return STRATUM_UNKNOWN;
    }
    stratum_method result = STRATUM_UNKNOWN;
    const rapidjson::Value& method = doc["method"];

    if (strcmp("mining.notify", method.GetString()) == 0) {
        result = MINING_NOTIFY;
    } else if (strcmp("mining.set_difficulty", method.GetString()) == 0) {
        result = MINING_SET_DIFFICULTY;
    }

    return result;
}

bool parse_mining_notify(std::string& line, mining_job& mJob)
{
    #ifdef VERBOSE
    std::cout << "    Parsing Method [MINING NOTIFY]" << std::endl;
    #endif
    if(!verifyPayload(line)) return false;
   
    if (doc.Parse(line.c_str()).HasParseError())
        return false;
    if (!doc.HasMember("params")) return false;

    const rapidjson::Value& params = doc["params"];
    
    if(!params[4].IsArray()) 
        return false;

    const rapidjson::Value& arMerkle = params[4].GetArray();
    
    mJob.job_id = std::string(params[0].GetString());
    mJob.prev_block_hash = std::string(params[1].GetString());
    mJob.coinb1 = std::string(params[2].GetString());
    mJob.coinb2 = std::string(params[3].GetString());

    mJob.merkle_branch.clear();
    for ( int i = 0; i < arMerkle.Size(); i++){
        mJob.merkle_branch.push_back(std::string(arMerkle[i].GetString()));
    }
    mJob.version = std::string(params[5].GetString());
    mJob.nbits = std::string(params[6].GetString());
    mJob.ntime = std::string(params[7].GetString());
    mJob.clean_jobs = params[8].GetBool();

    #ifdef DEBUG_MINING
    std::cout << "    job_id: " << mJob.job_id << std::endl;
    std::cout << "    prevhash: " << mJob.prev_block_hash << std::endl;
    std::cout << "    coinb1: " << mJob.coinb1 << std::endl;
    std::cout << "    coinb2: " << mJob.coinb2 << std::endl;
    std::cout << "    merkle_branch size: " << mJob.merkle_branch.size() << std::endl;
    std::cout << "    version: " << mJob.version << std::endl;
    std::cout << "    nbits: " << mJob.nbits << std::endl;
    std::cout << "    ntime: " << mJob.ntime << std::endl;
    std::cout << "    clean_jobs: " << mJob.clean_jobs << std::endl;
    #endif
    
    //Check if parameters where correctly received
    if (checkError(doc)) {
        #ifdef VERBOSE
        std::cout << "[WORKER] >>>>>>>>> Work aborted" << std::endl;
        #endif
        return false;
    }
    return true;
}

std::string toHex(unsigned long value) {
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(16);

    for (int i = sizeof(value) * 2 - 1; i >= 0; --i) {
        result.push_back(hex_digits[(value >> (i * 4)) & 0xF]);
    }

    return result;
}


bool tx_mining_submit(SimpleJsonRpcClient& client, mining_subscribe& mWorker, mining_job& mJob, unsigned long nonce)
{
    char payload[BUFFER] = {0};

    std::string hexNonce = toHex(nonce);

    // Submit
    id = getNextId(id);
    sprintf(payload, "{\"id\": %u, \"method\": \"mining.submit\", \"params\": [\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
        id,
        mWorker.wName,//"bc1qvv469gmw4zz6qa4u4dsezvrlmqcqszwyfzhgwj", //mWorker.name,
        mJob.job_id.c_str(),
        mWorker.extranonce2.c_str(),
        mJob.ntime.c_str(),
        hexNonce.c_str()
        );
    client.print(payload);
    #ifdef VERBOSE
    std::cout << "  Sending  : " << payload << std::endl;
    #endif

    return true;
}

bool parse_mining_set_difficulty(SimpleJsonRpcClient& client, std::string& line, double& difficulty)
{
    #ifdef VERBOSE
    std::cout << "    Parsing Method [SET DIFFICULTY]" << std::endl;
    #endif
    if(!verifyPayload(line)){
        tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
        return false;
    }
   
    if (doc.Parse(line.c_str()).HasParseError()){
        tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
        return false;
    }

    if (!doc.HasMember("params")){
        tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
        return false;
    }

    const rapidjson::Value& params = doc["params"];
    double diff = params[0].GetDouble();
    #ifdef VERBOSE
    std::cout << "    difficulty: " << diff << std::endl;
    #endif
    difficulty = diff;

    return true;
}

bool tx_suggest_difficulty(SimpleJsonRpcClient& client, double difficulty)
{
    char payload[BUFFER] = {0};

    id = getNextId(id);
    sprintf(payload, "{\"id\": %d, \"method\": \"mining.suggest_difficulty\", \"params\": [%.10g]}\n", id, difficulty);
    
    return client.print(payload);
}
