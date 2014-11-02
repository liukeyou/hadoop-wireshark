#ifndef __PROTOBUFHANDLEh
#define __PROTOBUFHANDLEh 

#include "config.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/io/coded_stream.h>
using namespace google::protobuf;
using namespace google::protobuf::compiler;
using namespace google::protobuf::internal;
	
#include <iostream>
#include <list>
using namespace std;

#include <glib.h>
#include "dirent.h"

#ifdef __cplusplus
extern "C" {
#endif 

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/filesystem.h>

struct Handles;
struct MethodInfo;

void register_protobuf_field(const FieldDescriptor* field, int proto_hadoop);
void register_protobuf_message(const Descriptor* message, int proto_hadoop);
void register_protobuf_file(string filePath, string fileName, int proto_hadoop);
void register_protobuf_files(string& pbFilePath, int proto_hadoop);
bool dissect_protobuf_by_name(const string msgName, tvbuff_t *tvb, guint* offset, proto_tree *tree, string& displayText, bool bVarintLen, guint16 lenByte);
bool dissect_protobuf_repeated_field(const FieldDescriptor* field, const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *leaf, int iRepeatedIndex);
bool dissect_protobuf_field(const FieldDescriptor* field, const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *leaf);
bool dissect_protobuf_message(const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *tree, string& displayText, bool bRoot);
bool read_varint32(tvbuff_t *tvb, guint* offset, uint32* value);
uint64 get_field_UInt64(const string& msgName, const string& fieldName, tvbuff_t *tvb, guint offset, bool bVarintLen, guint16 lenByte);

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

#ifdef __cplusplus
}
#endif 

#endif /* __PROTOBUFHANDLEh */