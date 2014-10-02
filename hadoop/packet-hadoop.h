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

// routines
void proto_register_hadoop(void);
void proto_reg_handoff_hadoop(void);

#ifdef __cplusplus
    }  // end of extern "C"
#endif

#endif

