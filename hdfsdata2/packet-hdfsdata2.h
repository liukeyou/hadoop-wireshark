/* packet-hadoop.h
  * header field declarations, value_string definitions, true_false_string 
  * definitions and function prototypes for main dissectors
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */

#ifndef PACKET_HADOOP_H
#define PACKET_HADOOP_H

#include "protobuf-handle.h"


#ifdef __cplusplus
    extern "C" {
#endif


struct CallInfo;
struct DataPacket;

typedef struct CallInfo
{
    uint srcPort;
    uint destPort;
    uint callId;
    
    bool operator < (const CallInfo& other) const
    {
        if (srcPort < other.srcPort)        
        {
           return true;
        }
        else if (srcPort == other.srcPort) 
        {
             if (destPort < other.destPort)
             {
                 return true;
             }
             else if (destPort == other.destPort)
             {
                 return callId < other.callId;
             }
        }
        
        return false;
    }
} CallInfo;

typedef struct DataPacket
{
    //address src;
    //address dst;
    uint srcPort;
    uint destPort;
    uint nxtseq;
    
    bool operator == (const DataPacket& other) 
    {
        if ( (srcPort  == other.srcPort) &&
             (destPort == other.destPort) && 
             (nxtseq   == other.nxtseq) )        
        {
           return true;
        }
        
        return false;
    }
    
    /*
    bool operator() (const DataPacket& dp)  
    {  
        return dp.srcPort==srcPort && dp.destPort==destPort && dp.nxtseq==nxtseq;  
    }
    
    bool operator < (const DataPacket& other) const
    {
        if (srcPort < other.srcPort)        
        {
           return true;
        }
        else if (srcPort == other.srcPort) 
        {
             if (destPort < other.destPort)
             {
                 return true;
             }
             else if (destPort == other.destPort)
             {
                 return nxtseq < other.nxtseq;
             }
        }
        
        return false;
    }*/
    
} DataPacket;

// routines
void proto_register_hadoop(void);
void proto_reg_handoff_hadoop(void);

#ifdef __cplusplus
    }  // end of extern "C"
#endif

#endif

