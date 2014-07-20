/* packet-hadoop.h
  * header field declarations, value_string definitions, true_false_string 
  * definitions and function prototypes for main dissectors
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */

#ifndef PACKET_HADOOP_H
#define PACKET_HADOOP_H

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct Handles
{
    int    p_id;
    string name;           
    string abbrev;
    
    const Descriptor* descriptor;
    gint * indices;

    Handles() : p_id( -1 ), descriptor( NULL ), indices( NULL ) 
    {
        indices  = new gint;
        *indices = -1;
    }
    
    ~Handles()
    {
        if (indices)
        {
           delete indices;
        }
    }
} Handles;

typedef struct MethodInfo
{
    string methodParamType;
    string methodReturnType;
} MethodInfo;

// routines
void proto_reg_handoff_hadoop(void);

#ifdef __cplusplus
    }  // end of extern "C"
#endif

#endif

