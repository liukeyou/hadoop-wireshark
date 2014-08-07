/* packet-hadoop.cpp
  * Routines for hadoop packet dissection
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */

#include "config.h"

#include <glib.h>

#include <iostream>
#include <list>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/io/coded_stream.h>
#include <dirent.h>

using namespace std;
using namespace google::protobuf;
using namespace google::protobuf::compiler;
using namespace google::protobuf::internal;

#include "packet-hadoop.h"

#ifdef __cplusplus
    extern "C" {
#endif

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/filesystem.h>

#define REQUEST_STR "hrpc"

static int proto_hadoop = -1;
static gint ett_hadoop = -1;

static int hf_hadoop_magic = -1;
static int hf_hadoop_version = -1;
static int hf_hadoop_serviceclass = -1;
static int hf_hadoop_authprotocol = -1;

map<string, Handles*>   g_mapHandles;
map<string, MethodInfo> g_mapMethod;
map<CallInfo, string>   g_mapCallInfo;
list<string>            g_listPBFile;   

bool dissect_protobuf_repeated_field(const FieldDescriptor* field, const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *leaf, int iRepeatedIndex)
{
    int len = 0;
    string scratch;

    if( !field->options().packed() )
    {
      len += WireFormat::TagSize( field->number(), field->type() );
    }

    map<string, Handles*>::iterator it = g_mapHandles.find( field->full_name() );
    if( it == g_mapHandles.end() )
    {
        return false; // bug
    }
    
    Handles* handles = it->second;
    const Reflection *reflection = message->GetReflection();
    const EnumValueDescriptor* enumDesc = NULL;

    switch( field->cpp_type() )
    {
    case FieldDescriptor::CPPTYPE_UINT32:
        if( field->type() == FieldDescriptor::TYPE_FIXED32 )
        {
            len += WireFormatLite::kFixed32Size;
        }
        else
        {
            len += WireFormatLite::UInt32Size( reflection->GetRepeatedUInt32( *message, field, iRepeatedIndex )  );      
        }
        proto_tree_add_uint( leaf, handles->p_id, tvb, *offset, len,  
			   reflection->GetRepeatedUInt32( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_INT32:
        if( field->type() == FieldDescriptor::TYPE_SFIXED32 )
        {
            len += WireFormatLite::kSFixed32Size;
        }
        else if( field->type() == FieldDescriptor::TYPE_SINT32 )
        {
            len += WireFormatLite::SInt32Size( reflection->GetRepeatedInt32( *message, field, iRepeatedIndex )  );	
        }
        else
        {
            len += WireFormatLite::Int32Size( reflection->GetRepeatedInt32( *message, field, iRepeatedIndex )  );	
        }
        proto_tree_add_int( leaf, handles->p_id, tvb, *offset, len,  
			      reflection->GetRepeatedInt32( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_FLOAT:
        len += WireFormatLite::kFloatSize;
        proto_tree_add_float( leaf, handles->p_id, tvb, *offset, len,  
			    reflection->GetRepeatedFloat( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_UINT64:
        if( field->type() == FieldDescriptor::TYPE_FIXED64 )
        {
            len += WireFormatLite::kFixed64Size;
        }
        else
        {
            len += WireFormatLite::UInt64Size( reflection->GetRepeatedUInt64( *message, field, iRepeatedIndex )  );	
        }
        proto_tree_add_uint64( leaf, handles->p_id, tvb, *offset, len,  
			     reflection->GetRepeatedUInt64( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_INT64:
        if( field->type() == FieldDescriptor::TYPE_SFIXED64 )
        {
            len += WireFormatLite::kSFixed64Size;
        }
        else if( field->type() == FieldDescriptor::TYPE_SINT64 )
        {
            len += WireFormatLite::SInt64Size( reflection->GetRepeatedInt64( *message, field, iRepeatedIndex )  );	
        }
      else
        {
            len += WireFormatLite::Int64Size( reflection->GetRepeatedInt64( *message, field, iRepeatedIndex )  );	
        }
        proto_tree_add_int64( leaf, handles->p_id, tvb, *offset, len,  
			    reflection->GetRepeatedInt64( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_DOUBLE:
        len += WireFormatLite::kDoubleSize;
        proto_tree_add_double( leaf, handles->p_id, tvb, *offset, len,  
			     reflection->GetRepeatedDouble( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_BOOL:
        len += WireFormatLite::kBoolSize;
        proto_tree_add_boolean( leaf, handles->p_id, tvb, *offset, len,
			      reflection->GetRepeatedBool( *message, field, iRepeatedIndex ) );
      break;
    case FieldDescriptor::CPPTYPE_ENUM:
        enumDesc = reflection->GetRepeatedEnum( *message, field, iRepeatedIndex );
        len += WireFormatLite::EnumSize( enumDesc->number() );
        proto_tree_add_int_format_value( leaf, handles->p_id, tvb, *offset, len, 
				       enumDesc->number(), "%d ( %s )", enumDesc->number(),
				       enumDesc->name().c_str() );
      break;
    case FieldDescriptor::CPPTYPE_STRING:
        len += WireFormatLite::StringSize( reflection->GetRepeatedStringReference( *message, field, iRepeatedIndex, &scratch ) );
        proto_tree_add_string( leaf, handles->p_id, tvb, *offset, len,  
			     reflection->GetRepeatedString( *message, field, iRepeatedIndex ).c_str() );
      break;
    default:
        proto_tree_add_item( leaf, handles->p_id, tvb, *offset, len, true );
    };

    *offset += len;
    
    return true;
}

bool dissect_protobuf_field(const FieldDescriptor* field, const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *leaf)
{
    int len = WireFormat::FieldByteSize( field, *message );

    map<string, Handles*>::iterator it = g_mapHandles.find( field->full_name() );
    if( it == g_mapHandles.end() )
    {
        return false; // bug
    }
    
    Handles* handles = it->second;
    const Reflection *reflection = message->GetReflection();
    const EnumValueDescriptor* enumDesc = NULL;

    switch( field->cpp_type() )
    {
    case FieldDescriptor::CPPTYPE_UINT32:
      proto_tree_add_uint( leaf, handles->p_id, tvb, *offset, len,
               reflection->GetUInt32( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_INT32:
      proto_tree_add_int( leaf, handles->p_id, tvb, *offset, len, 
              reflection->GetInt32( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_FLOAT:
      proto_tree_add_float( leaf, handles->p_id, tvb, *offset, len, 
                reflection->GetFloat( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_UINT64:
      proto_tree_add_uint64( leaf, handles->p_id, tvb, *offset, len, 
                 reflection->GetUInt64( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_INT64:
      proto_tree_add_int64( leaf, handles->p_id, tvb, *offset, len, 
                reflection->GetInt64( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_DOUBLE:
      proto_tree_add_double( leaf, handles->p_id, tvb, *offset, len, 
                 reflection->GetDouble( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_BOOL:
      proto_tree_add_boolean( leaf, handles->p_id, tvb, *offset, len, 
                  reflection->GetBool( *message, field ) );
      break;
    case FieldDescriptor::CPPTYPE_ENUM:
      enumDesc = reflection->GetEnum( *message, field );
      proto_tree_add_int_format_value( leaf, handles->p_id, tvb, *offset, len, 
                       enumDesc->number(), "%d ( %s )", enumDesc->number(), enumDesc->name().c_str() );
      break;
    case FieldDescriptor::CPPTYPE_STRING:
      proto_tree_add_string( leaf, handles->p_id, tvb, *offset, len, 
                 reflection->GetString( *message, field ).c_str() );
      break;
    default:
      proto_tree_add_item( leaf, handles->p_id, tvb, *offset, len, true );
    };

    *offset += len;
}

bool dissect_protobuf_message(const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *tree, string& displayText, bool bRoot)
{
	string fullName = message->GetDescriptor()->full_name();
    map<string, Handles*>::iterator it = g_mapHandles.find( message->GetDescriptor()->full_name() );
    if( it == g_mapHandles.end() )
    {
        return false; // bug
    }
    
    int iMsgLen = message->ByteSize();
    // if not root field then submessage needs to be computed
    if( !bRoot )
    {
      *offset += WireFormat::TagSize( message->GetDescriptor()->index(), FieldDescriptor::TYPE_MESSAGE );
      *offset += io::CodedOutputStream::VarintSize32( iMsgLen );
    }
    
    Handles* handles = it->second;
    proto_item* item = proto_tree_add_none_format( tree, handles->p_id, tvb, *offset, iMsgLen, "%s",displayText.c_str() );
    proto_tree* subTree = proto_item_add_subtree( item, *(handles->indices) );
      
    const Reflection *reflection = message->GetReflection();
    // dissect field
    vector<const FieldDescriptor*> fieldList;
    reflection->ListFields(*message, &fieldList);
    for( vector<const FieldDescriptor*>::iterator itField = fieldList.begin(); itField!=fieldList.end(); itField++ )
    {
        const FieldDescriptor* field = *itField;
        bool bMessage = ( FieldDescriptor::CPPTYPE_MESSAGE == field->cpp_type() );
            
        if (field->is_repeated())
        {
            int iRepeatedSize = reflection->FieldSize( *message, field );
            for( int iRepeatedIndex = 0; iRepeatedIndex < iRepeatedSize; iRepeatedIndex++ )
            {
                if (bMessage)
                {
                    const Message& subMessage = reflection->GetRepeatedMessage( *message, field, iRepeatedIndex );
                    dissect_protobuf_message(&subMessage, tvb, offset, subTree, string(field->name()), false);
                }
                else
                {
                    dissect_protobuf_repeated_field(field, message, tvb, offset, subTree, iRepeatedIndex);
                }
            }
        }
        else
        {
            if (bMessage)
            {
                const Message& subMessage = reflection->GetMessage( *message, field );
                
                dissect_protobuf_message(&subMessage, tvb, offset, subTree, string(field->name()), false);
            }
            else
            {
                dissect_protobuf_field(field, message, tvb, offset, subTree);
            }
        }
        
    } // end for (int iFieldIndex = 0; iFieldIndex < message->field_count(); iFieldIndex++) 
        
    return true;
}

bool read_varint32(tvbuff_t *tvb, guint* offset, uint32* value)
{
    uint codeLen = tvb_reported_length(tvb) - *offset;
    
    io::CodedInputStream cis(tvb_get_ptr(tvb, *offset, codeLen), codeLen);
    
    bool bRet = cis.ReadVarint32(value);
    if (bRet)
    {
        *offset += io::CodedOutputStream::VarintSize32( *value );
    }
    
    return bRet; 
}

bool dissect_rpcBody(tvbuff_t *tvb, guint* offset, proto_tree *tree, string& rpcMethodParam)
{
    uint32 rpcParamLen = 0;
    if (!read_varint32(tvb, offset, &rpcParamLen))
    {
        return false;
    }
    
	if (0 == rpcParamLen)
	{
		return true;
	}

    const guint8* rpcParamBuf = tvb_get_ptr(tvb, *offset, rpcParamLen);
    
    map<string, Handles*>::iterator itParam = g_mapHandles.find( rpcMethodParam );
    if( itParam == g_mapHandles.end() ) 
    {
        return false; // bug
    }
    
    DynamicMessageFactory factory;
    Handles* handles = itParam->second;
    const Message *message = NULL;
    message = factory.GetPrototype(handles->descriptor);
    Message *rpcParamMessage = message->New();
    if (rpcParamMessage->ParseFromArray(rpcParamBuf, rpcParamLen))
    {
        dissect_protobuf_message(rpcParamMessage, tvb, offset, tree, rpcMethodParam, true);
        
        return true;
    }
}


bool dissect_rpcheader(tvbuff_t *tvb, guint* offset, proto_tree *tree, bool* bRequest, int *callId)
{
    uint32 rpcHeaderLen = 0;
    if (!read_varint32(tvb, offset, &rpcHeaderLen))
    {
        return false;
    }

    const guint8* rpcHeaderBuf = tvb_get_ptr(tvb, *offset, rpcHeaderLen);
    
    *bRequest = true;
    // first find hadoop common rpcheader
    map<string, Handles*>::iterator itRequest = g_mapHandles.find( "hadoop.common.RpcRequestHeaderProto" );
    if( itRequest == g_mapHandles.end() ) 
    {
        return false; // bug
    }
    
    DynamicMessageFactory factory;
    Handles* handles = itRequest->second;
    const Message *message = NULL;
    message = factory.GetPrototype(handles->descriptor);
    Message *reqMessage = message->New();
    if (reqMessage->ParseFromArray(rpcHeaderBuf,rpcHeaderLen))
    {
        dissect_protobuf_message(reqMessage, tvb, offset, tree, string("RpcRequestHeaderProto"), true);
        *bRequest = true;
        
        // get callid for response
        const FieldDescriptor *field = NULL;
        field = reqMessage->GetDescriptor()->FindFieldByName("callId");
        const Reflection* reflection = reqMessage->GetReflection();
        *callId = reflection->GetInt32(*reqMessage, field);
        
        return true;
    }
    else
    {
          // maybe response
        map<string, Handles*>::iterator itResponse = g_mapHandles.find( "hadoop.common.RpcResponseHeaderProto" );
        if( itResponse == g_mapHandles.end() )
        {
            return false; // bug
        }
        
        handles = itResponse->second;
        message = factory.GetPrototype(handles->descriptor);
        Message *responseMessage = message->New();
        if (responseMessage->ParseFromArray(rpcHeaderBuf,rpcHeaderLen))
        {
            dissect_protobuf_message(responseMessage, tvb, offset, tree, string("RpcResponseHeaderProto"), true);
            *bRequest = false;
            
            // get callid 
            const FieldDescriptor *field = NULL;
            field = responseMessage->GetDescriptor()->FindFieldByName("callId");
            const Reflection* reflection = responseMessage->GetReflection();
            *callId = reflection->GetUInt32(*responseMessage, field);

            return true;
        }
        
        return false; // not rpcheader
    }
    
}

bool dissect_reqheader(tvbuff_t *tvb, guint* offset, proto_tree *tree, string& rpcMethodName)
{
    uint32 reqHeaderLen = 0;
    if (!read_varint32(tvb, offset, &reqHeaderLen))
    {
        return false;
    }
    const guint8* reqHeaderBuf = tvb_get_ptr(tvb, *offset, reqHeaderLen);
    
    map<string, Handles*>::iterator itRequest = g_mapHandles.find( "hadoop.common.RequestHeaderProto" );
    if( itRequest == g_mapHandles.end() ) 
    {
        return false; // bug
    }
    
    DynamicMessageFactory factory;
    Handles* handles = itRequest->second;
    const Message *message = NULL;
    message = factory.GetPrototype(handles->descriptor);
    Message *reqHeaderMessage = message->New();
    if (reqHeaderMessage->ParseFromArray(reqHeaderBuf, reqHeaderLen))
    {
        dissect_protobuf_message(reqHeaderMessage, tvb, offset, tree, string("RequestHeaderProto"), true);
        
        const FieldDescriptor *field = NULL;
        field = reqHeaderMessage->GetDescriptor()->FindFieldByName("methodName");
        const Reflection* reflection = reqHeaderMessage->GetReflection();
        rpcMethodName = reflection->GetString(*reqHeaderMessage, field);
        
        return true;
    }
}

bool dissect_hadoop_rpc(tvbuff_t *tvb, guint* offset, proto_tree *hadoop_tree, packet_info *pinfo)
{
    bool bRequst = true;
    int  callId = 0;
    
    dissect_rpcheader(tvb, offset, hadoop_tree, &bRequst, &callId);
    if (bRequst)
    {
		if (callId == -3) // final static int CONNECTION_CONTEXT_CALL_ID = -3;
		{
			dissect_rpcBody(tvb, offset, hadoop_tree, string("hadoop.common.IpcConnectionContextProto"));
		    return true;
		}
		else if (callId == -33) // AuthProtocol.NONE? || AuthProtocol.SASL
		{
			// RpcSaslProto
			dissect_rpcBody(tvb, offset, hadoop_tree, string("hadoop.common.RpcSaslProto"));
		    return true;
		}

        string rpcMethodName;
        dissect_reqheader(tvb, offset, hadoop_tree, rpcMethodName);
    
        // find rpcMethodParam
        map<string, MethodInfo>::iterator itMethod = g_mapMethod.find( rpcMethodName );
        if( itMethod != g_mapMethod.end() )
        {
             MethodInfo methodInfo = itMethod->second;
         
             dissect_rpcBody(tvb, offset, hadoop_tree, methodInfo.methodParamType);
         
             // add returnType for response
			 CallInfo callInfo;
			 callInfo.callId   = callId;
			 callInfo.srcPort  = pinfo->srcport;
			 callInfo.destPort = pinfo->destport;

             map<CallInfo, string>::iterator itCallInfo = g_mapCallInfo.find( callInfo );
             if (itCallInfo == g_mapCallInfo.end())
             {
                 g_mapCallInfo.insert( pair<CallInfo, string>( callInfo, methodInfo.methodReturnType ) );
             }
        }
    } else { // response
		if (callId == -33) // AuthProtocol.SASL
		{
			dissect_rpcBody(tvb, offset, hadoop_tree, string("hadoop.common.RpcSaslProto"));
		    return true;
		}
		
		CallInfo callInfo;
		callInfo.callId   = callId;
		callInfo.srcPort  = pinfo->destport;
		callInfo.destPort = pinfo->srcport;

        map<CallInfo, string>::iterator itCallInfo = g_mapCallInfo.find( callInfo );
        if (itCallInfo != g_mapCallInfo.end())
        {
             dissect_rpcBody(tvb, offset, hadoop_tree, itCallInfo->second);
        }
    }
    
    return true;
}

bool dissect_hadoop_handshake(tvbuff_t *tvb, guint* offset, proto_tree *hadoop_tree)
{
    proto_tree_add_item(hadoop_tree, hf_hadoop_magic, tvb, *offset, sizeof(REQUEST_STR) - 1, ENC_ASCII|ENC_NA);
    *offset += (int)sizeof(REQUEST_STR) - 1;

    proto_tree_add_item(hadoop_tree, hf_hadoop_version, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;

    proto_tree_add_item(hadoop_tree, hf_hadoop_serviceclass, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;
    
    proto_tree_add_item(hadoop_tree, hf_hadoop_authprotocol, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;
    
    return true;
}

bool dissect_rpc_packet(tvbuff_t *tvb, guint *offset, proto_tree *hadoop_tree, string& packetName, string& displayName)
{
    guint len = tvb_get_ntohl(tvb, *offset);
	*offset += 4;
    const guint8* buf1 = tvb_get_ptr(tvb, *offset, len);
    *offset += len;

	len = tvb_get_ntohl(tvb, *offset);
	*offset += 4;
	
	const guint8* buf = tvb_get_ptr(tvb, *offset, len);

    map<string, Handles*>::iterator it = g_mapHandles.find( packetName );
    if( it == g_mapHandles.end() ) 
    {
        return false; // bug
    }
    
    DynamicMessageFactory factory;
    Handles* handles = it->second;
    const Message *message = NULL;
    message = factory.GetPrototype(handles->descriptor);
    Message *messagePacket = message->New();
    if (messagePacket->ParseFromArray(buf, len))
    {
        dissect_protobuf_message(messagePacket, tvb, offset, hadoop_tree, displayName, true);
        
        return true;
    }
    
    return false;
}

static void dissect_hadoop_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset  = 0;
    guint length  = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HADOOP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    
    if (tree) 
    {
        proto_item *ti = NULL;
        proto_tree *hadoop_tree = NULL;
    
        /* check the packet length */           
        guint auth = tvb_get_ntohl(tvb, offset);
    
        ti = proto_tree_add_item(tree, proto_hadoop, tvb, 0, -1, ENC_NA);
        hadoop_tree = proto_item_add_subtree(ti, ett_hadoop);
        
        /* first setup packet starts with "hrpc" */
        if (!tvb_memeql(tvb, offset, (const guint8 *)REQUEST_STR, sizeof(REQUEST_STR) - 1)) 
        {
            dissect_hadoop_handshake(tvb, &offset, hadoop_tree);
        } 
        else 
        {
            /* second authentication packet */
            if (auth + 4 != tvb_reported_length(tvb)) 
			{
				        // TODO ??????????????????
                    /* authentication length (read out of first 4 bytes) */
                    //length = tvb_get_ntohl(tvb, offset);
                    //proto_tree_add_item(hdfs_tree, hf_hdfs_authlen, tvb, offset, 4, ENC_ASCII|ENC_NA);
                    offset += 4;
            
                    /* authentication (length the number we just got) */
                    //proto_tree_add_item(hdfs_tree, hf_hdfs_auth, tvb, offset, length, ENC_ASCII|ENC_NA);
                    //offset += length;
					dissect_hadoop_rpc(tvb, &offset, hadoop_tree, pinfo);
			    // IpcConnectionContextProto
			    //dissect_rpc_packet (tvb, &offset, hadoop_tree, 
                //	   string("hadoop.common.IpcConnectionContextProto"), string("IpcConnectionContextProto") );
            }

            offset += 4; // length
            dissect_hadoop_rpc(tvb, &offset, hadoop_tree, pinfo);
        }
    } // end of if (tree)
    
    //return tvb_length(tvb);
}



// determine PDU length of protocol 
static guint get_hadoop_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_)
{
    offset  = 0;
	int len = tvb_reported_length(tvb);
	guint protobufLen = tvb_get_ntohl(tvb, offset);

	if (!tvb_memeql(tvb, offset, (const guint8 *)REQUEST_STR, sizeof(REQUEST_STR) - 1)) 
	{
		/* first setup packet starts with "hrpc" */
	}else{
		if (protobufLen + 4 > len)
		{
			len = protobufLen + 4;
		} else if (protobufLen + 4 < len){
			offset += 4;
			offset += protobufLen;
			guint nextPacketLen = tvb_get_ntohl(tvb, offset);
			if (nextPacketLen + 4 > tvb_reported_length_remaining(tvb, offset))
			{
				len = nextPacketLen + 4 + protobufLen + 4;
			}
		}
    }

    return len;

}

static void dissect_hadoop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int frame_header_len = 0;
    gboolean need_reassemble = FALSE;
	guint offset  = 0;

    frame_header_len = tvb_reported_length(tvb);
	guint protobufLen = tvb_get_ntohl(tvb, offset);

	if (!tvb_memeql(tvb, offset, (const guint8 *)REQUEST_STR, sizeof(REQUEST_STR) - 1)) 
	{
		/* first setup packet starts with "hrpc" */
	}else{
		if (protobufLen + 4 > frame_header_len)
		{
			need_reassemble = TRUE;
		} else if (protobufLen + 4 < frame_header_len){
			offset += 4;
			offset += protobufLen;
			guint nextPacketLen = tvb_get_ntohl(tvb, offset);
			if (nextPacketLen + 4 > tvb_reported_length_remaining(tvb, offset))
			{
				need_reassemble = TRUE;
			}
		}
    }

    tcp_dissect_pdus(tvb, pinfo, tree, need_reassemble, frame_header_len, get_hadoop_message_len, dissect_hadoop_message);
}

void register_protobuf_field(const FieldDescriptor* field)
{
    ftenum         type    = FT_NONE;
    base_display_e display = BASE_NONE;
    
    switch( field->cpp_type() )
    {
        case FieldDescriptor::CPPTYPE_INT32:
            type    = FT_INT32;
            display = BASE_DEC;
            break;
        case FieldDescriptor::CPPTYPE_INT64:
            type    = FT_INT64;
            display = BASE_DEC;
            break;
        case FieldDescriptor::CPPTYPE_UINT32:
            type    = FT_UINT32;
              display = BASE_HEX;
            break;
        case FieldDescriptor::CPPTYPE_UINT64:
            type    = FT_UINT64;
            display = BASE_HEX;    
            break;
        case FieldDescriptor::CPPTYPE_DOUBLE:
            type    = FT_DOUBLE;
            display = BASE_NONE;
            break;
        case FieldDescriptor::CPPTYPE_FLOAT:
            type    = FT_FLOAT;
            display = BASE_NONE;
            break;
        case FieldDescriptor::CPPTYPE_BOOL:
            type    = FT_BOOLEAN;
              display = BASE_NONE;
            break;
        case FieldDescriptor::CPPTYPE_ENUM:
            type    = FT_INT32;
              display = BASE_DEC;
            break;
        case FieldDescriptor::CPPTYPE_STRING:
            type    = FT_STRING;
              display = BASE_NONE;
            break;
        case FieldDescriptor::CPPTYPE_MESSAGE:
            return;
            break;
        default:
            type    = FT_NONE;
              display = BASE_NONE;
            break;
    }
    
    Handles *handles = new Handles;
    handles->name   = field->full_name();
    handles->abbrev = field->name();

    hf_register_info message_info =
        { &(handles->p_id),
            { (char*)(handles->name.c_str()),
              (char*)(handles->abbrev.c_str()),
              type,
              display,
              NULL, 0,
              "",
              HFILL
            }
        };
  
    hf_register_info *hf_info = (hf_register_info *)malloc(sizeof( hf_register_info ) );
    *hf_info = message_info;

    proto_register_field_array( proto_hadoop, hf_info, 1 );

    g_mapHandles.insert( pair<string, Handles*>( handles->name, handles ) );
    
}

void register_protobuf_message(const Descriptor* message)
{
    if (NULL == message)
    {
        return;
    }
    
    // skip repeated message
    map<string, Handles*>::iterator it = g_mapHandles.find( message->full_name() );
    if( it != g_mapHandles.end() ) 
    {
      return;
    }
    
	// handle nest message
	int iNestCount = message->nested_type_count();
	for (int iNestIndex = 0; iNestIndex < iNestCount; iNestIndex++)
	{
		const Descriptor* nestMessage = message->nested_type(iNestIndex);
		register_protobuf_message(nestMessage);
	}

    Handles* handles = new Handles();
    handles->name   = message->full_name();
    handles->abbrev = message->name();
    handles->descriptor = message;
    
    hf_register_info message_info =
        { &(handles->p_id),
            { (char*)(handles->name.c_str()),
              (char*)(handles->abbrev.c_str()),
              FT_NONE,
              BASE_NONE,
              NULL, 0,
              "",
              HFILL
            }
        };
  
    hf_register_info *hf_info = (hf_register_info *)malloc(sizeof( hf_register_info ) );
    *hf_info = message_info;

    proto_register_field_array( proto_hadoop, hf_info, 1 );
    proto_register_subtree_array( &(handles->indices), 1 );

    g_mapHandles.insert( pair<string, Handles*>( handles->name, handles ) );
    
    // parse field
    for (int iFieldIndex = 0; iFieldIndex < message->field_count(); iFieldIndex++)
    {
        const FieldDescriptor* fieldDescriptor = message->field(iFieldIndex);
        register_protobuf_field(fieldDescriptor);
    }

}

void register_protobuf_file(string filePath, string fileName)
{
    if ( g_listPBFile.end() != find(g_listPBFile.begin(), g_listPBFile.end(), filePath + fileName ) )
    {
        return;
    }
    g_listPBFile.push_back( filePath + fileName );
      
    DiskSourceTree sourceTree;
    sourceTree.MapPath("", filePath);
    
    // keep the Descriptor data in memory  
    Importer* importer = new Importer(&sourceTree, NULL);
                
    const FileDescriptor* file = NULL;
    file = importer->Import(fileName);
    if (NULL == file)
    {
        return;
    }

    // recursive parse import file
    for (int iDependencyIndex = 0; iDependencyIndex < file->dependency_count(); iDependencyIndex++)
    {
        const FileDescriptor* dependencyFile = NULL;
        dependencyFile = file->dependency(iDependencyIndex);
        if (NULL == dependencyFile)
        {
            return;
        }

        register_protobuf_file(filePath, dependencyFile->name());
    }
    
    // parse message
    for (int iMsgIndex = 0; iMsgIndex < file->message_type_count(); iMsgIndex++)
    {
            const Descriptor* message = file->message_type(iMsgIndex);
            register_protobuf_message(message);
    }
      
    // parse service
    for (int iServiceIndex = 0; iServiceIndex < file->service_count(); iServiceIndex++)
    {
        const ServiceDescriptor* service = file->service(iServiceIndex);
        for (int iMethodIndex = 0; iMethodIndex < service->method_count(); iMethodIndex++)
        {
            const MethodDescriptor* method = service->method(iMethodIndex);
            
            MethodInfo methodInfo;
            methodInfo.methodParamType = method->input_type()->full_name();
            methodInfo.methodReturnType = method->output_type()->full_name();
            
            g_mapMethod.insert(pair<string, MethodInfo>(method->name(), methodInfo));
        }
    } // end parse service
    
}

void register_protobuf_files(string& pbFilePath)
{   
    DIR *dir;
    struct dirent *ent;
    
    dir = opendir (pbFilePath.c_str());
    if (dir != NULL) 
    {
        string filePath;
        while ((ent = readdir (dir)) != NULL) 
        {
			if (string(ent->d_name) == "." || string(ent->d_name) == "..")
			{
				continue;
			}

            switch (ent->d_type) {
            case DT_REG:
                register_protobuf_file (pbFilePath, ent->d_name);
                break;
            case DT_DIR:
                  filePath = pbFilePath + "/" + ent->d_name;
                register_protobuf_files (filePath);
                break;
            case DT_LNK:
            default:
                  continue;
            }
        }

        closedir (dir);
    }
    else
    {
        // bug
    }
}


void proto_register_hadoop(void)
{
    
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hadoop
    };
    
    module_t *hadoop_module;

    proto_hadoop = proto_register_protocol (
        "HADOOP Protocol", /* name       */
        "HADOOP",      /* short name */
        "hadoop"       /* abbrev     */
        );
    static hf_register_info hf[] = {

        /*************************************************
        handshake packet
        **************************************************/
        { &hf_hadoop_magic,
          { "HADOOP protocol magic", "hadoop.magic",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hadoop_version,
          { "HADOOP protocol version", "hadoop.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hadoop_serviceclass,
          { "HADOOP ServiceClass", "hadoop.service_class",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hadoop_authprotocol,
          { "HADOOP AuthProtocol", "hadoop.auth_protocol",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };
    
    proto_register_field_array(proto_hadoop, hf, array_length(hf));
    
    string pbFilePath = get_plugin_dir();
    pbFilePath += "/hadoop-wireshark/hadoop";

    register_protobuf_files(pbFilePath);
    
    proto_register_subtree_array(ett, array_length(ett));
    
    hadoop_module = prefs_register_protocol(proto_hadoop, proto_reg_handoff_hadoop);

    //new_register_dissector("hadoop", dissect_hadoop, proto_hadoop);
	register_dissector("hadoop", dissect_hadoop, proto_hadoop);
}

void proto_reg_handoff_hadoop(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t hadoop_handle;

    if (!initialized) 
	{
        hadoop_handle = find_dissector("hadoop");
        dissector_add_handle("tcp.port", hadoop_handle);  /* for "decode as" */
        initialized = TRUE;
    } 
}

#ifdef __cplusplus
    }  // end of extern "C"
#endif