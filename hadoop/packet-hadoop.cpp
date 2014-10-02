/* packet-hadoop.cpp
  * Routines for hadoop packet dissection
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */
#include "packet-hadoop.h"

#define REQUEST_STR "hrpc"

static int proto_hadoop = -1;
static gint ett_hadoop = -1;

static int hf_hadoop_magic = -1;
static int hf_hadoop_version = -1;
static int hf_hadoop_serviceclass = -1;
static int hf_hadoop_authprotocol = -1;

map<CallInfo, string>          g_mapCallInfo;
extern map<string, Handles*>   g_mapHandles;
extern map<string, MethodInfo> g_mapMethod;

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

    register_protobuf_files(pbFilePath, proto_hadoop);
    
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

