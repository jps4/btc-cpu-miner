#include <thread>
#include <vector>

#include <iostream>
#include <iomanip>

#include <csignal>
#include <cstdlib>

#include "version.h"
#include "mining.h"
#include "utils.h"

#include "drivers/storage/storage.h"

TSettings Settings;

volatile sig_atomic_t sigint_received = false;
int mining_threads;

void sigint_handler(int signal) {
    std::cout << "SIGINT (Ctrl+C), killing..." << std::endl;
    sigint_received = true;
}

int main() {
    std::signal(SIGINT, sigint_handler);

    std::cout << NAME << "-" << CURRENT_VERSION << " starting......" << std::endl;

    std::thread stratumThread(runStratumWorker, nullptr);

    mining_threads = DEFAULT_MINING_THREADS;
    const char* mining_threads_str = std::getenv(ENV_MINING_THREADS);
    if (mining_threads_str != nullptr){
        try{
            mining_threads = std::stoi(mining_threads_str);
            if (mining_threads > MAX_MINING_THREADS)
                mining_threads = MAX_MINING_THREADS;
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: " << mining_threads_str << " not a valid number, defaulting to " << DEFAULT_MINING_THREADS << std::endl;
        } catch (const std::out_of_range& e) {
            std::cerr << "Error: " << mining_threads_str << " out of range, defaulting to " << DEFAULT_MINING_THREADS << std::endl;
        }
    }
    #ifdef VERBOSE
    std::cout << "Starting Miners (" << mining_threads << ")..." << std::endl;
    #endif
    
    std::vector<std::thread> minerThreads;
    int i;
    for ( i = 0; i < mining_threads; i++){
        minerThreads.emplace_back([i](){ runMiner(i); });
    }

    std::thread monitorStatsThread(runMonitorStats, nullptr);

    stratumThread.join();
    for (auto& thread : minerThreads) {
        thread.join();
    }

    monitorStatsThread.join();

};


