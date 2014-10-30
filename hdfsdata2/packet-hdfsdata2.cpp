/* packet-hdfsdata2.cpp
  * Routines for hadoop packet dissection
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */

#include "packet-hdfsdata2.h"

#define REQUEST_STR "hrpc"

static int proto_hadoop = -1;
static gint ett_hadoop = -1;

static int hf_hadoop_magic = -1;
static int hf_hadoop_version = -1;
static int hf_hadoop_serviceclass = -1;
static int hf_hadoop_authprotocol = -1;

extern map<string, Handles*>    g_mapHandles;
extern map<string, MethodInfo>  g_mapMethod;
map<CallInfo, string>           g_mapCallInfo;
map<unsigned int, unsigned int> g_mapSeqNumber;



bool dissect_xceiver_op(tvbuff_t *tvb, packet_info *pinfo, guint* offset, proto_tree *hadoop_tree)
{
    guint16 version = tvb_get_ntohs(tvb, *offset);
    *offset += 2;
    guint8 opcode = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    
    //WRITE_BLOCK((byte)80),
    //READ_BLOCK((byte)81),
    //READ_METADATA((byte)82),
    //REPLACE_BLOCK((byte)83),
    //COPY_BLOCK((byte)84),
    //BLOCK_CHECKSUM((byte)85),
    //TRANSFER_BLOCK((byte)86),
    //REQUEST_SHORT_CIRCUIT_FDS((byte)87),
    //RELEASE_SHORT_CIRCUIT_FDS((byte)88),
    //REQUEST_SHORT_CIRCUIT_SHM((byte)89);
    string opclass = "hadoop.hdfs.";
    switch (opcode)
    {
        case 80: //WRITE_BLOCK
             opclass += "OpWriteBlockProto";
             if ( pinfo->private_data != NULL)
        	 {
        		 tcpinfo *ti = (tcpinfo *)(pinfo->private_data); 
        		 ti->seq;
        		 ti->nxtseq;
        		
        		 map<unsigned int, unsigned int>::iterator itSeqNumber = g_mapSeqNumber.find( ti->seq );
                 if (itSeqNumber == g_mapSeqNumber.end())
                 {
                     g_mapSeqNumber.insert( pair<unsigned int, unsigned int>( ti->seq, ti->nxtseq) );
                 }
                 else
                 {
                    g_mapSeqNumber[ti->seq] = ti->nxtseq;
                 }
        	 }
        break;
        case 81: //READ_BLOCK
             opclass += "OpReadBlockProto";
        break;
        case 82: //READ_METADATA
             opclass += ""; // reserver
        break;
        case 83: //REPLACE_BLOCK
             opclass += "OpReplaceBlockProto";
        break;
        case 84: //COPY_BLOCK
             opclass += "OpCopyBlockProto";
        break;
        case 85: //BLOCK_CHECKSUM
             opclass += "OpBlockChecksumProto";
        break;
        case 86: //TRANSFER_BLOCK
             opclass += "OpTransferBlockProto";
        break;
        case 87: //REQUEST_SHORT_CIRCUIT_FDS
             opclass += "OpRequestShortCircuitAccessProto";
        break;
        case 88: //RELEASE_SHORT_CIRCUIT_FDS
             opclass += "ReleaseShortCircuitAccessRequestProto";
        break;
        case 89: //REQUEST_SHORT_CIRCUIT_SHM
             opclass += "ShortCircuitShmRequestProto";
        break;
        default:
            return false;
    }
    
    return dissect_protobuf_by_name(opclass, tvb, offset, hadoop_tree, opclass, true, 4);
}

bool dissect_write_block(tvbuff_t *tvb, guint* offset, proto_tree *hadoop_tree)
{
    // get packet lentch
    guint packetLen = tvb_get_ntohl(tvb, *offset);
    *offset += 4;
    
    // get hearder lentch
    guint16 hearderLen = tvb_get_ntohs(tvb, *offset);
    
    if ( !dissect_protobuf_by_name("hadoop.hdfs.PacketHeaderProto", tvb, offset, hadoop_tree, string("hadoop.hdfs.PacketHeaderProto"), false, 2) )
    {
        return false;
    }
    
    if ( tvb_reported_length(tvb) != packetLen + hearderLen + 2 )
    {
        return false;
    }    
}

static void dissect_hadoop_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset  = 0;
    guint length  = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDFSDATA2");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    
    if (tree) 
    {
        proto_item *ti = NULL;
        proto_tree *hadoop_tree = NULL; 
    
        ti = proto_tree_add_item(tree, proto_hadoop, tvb, 0, -1, ENC_NA);
        hadoop_tree = proto_item_add_subtree(ti, ett_hadoop);
        
        length = tvb_reported_length(tvb);
            
        // maby xceiver op            
        guint16 version = tvb_get_ntohs(tvb, offset);
        if (28 == version)
        {
            if(dissect_xceiver_op(tvb, pinfo, &offset, hadoop_tree))
            {
                return;    
            }
        }
        offset = 0;
        
        // maby write block
        if (length >= 31)
        {
            if(dissect_write_block(tvb, &offset, hadoop_tree))
            {
                return;    
            }
        }
        offset = 0;
        
        // maby BlockOpResponseProto
        if ( dissect_protobuf_by_name("hadoop.hdfs.BlockOpResponseProto", tvb, &offset, hadoop_tree, string("hadoop.hdfs.BlockOpResponseProto"), true, 4) )
        {
            return;
        }
        
        
        
    } // end of if (tree)

}

// determine PDU length of protocol 
static guint get_hadoop_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_)
{
    offset  = 0;
	int packetLen = tvb_reported_length(tvb);
	
    // maybe data
    if (packetLen >= 31)
    {
        guint dataLen = tvb_get_ntohl(tvb, offset);
        
    }
/*
	if (!tvb_memeql(tvb, offset, (const guint8 *)REQUEST_STR, sizeof(REQUEST_STR) - 1)) 
	{
		
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
    */
    
    return tvb_reported_length(tvb);
}

static void dissect_hadoop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int frame_header_len = 0;
    gboolean need_reassemble = FALSE;
    guint offset  = 0;

    frame_header_len = tvb_reported_length(tvb);
    guint protobufLen = tvb_get_ntohl(tvb, offset);

	
/*
    if (!tvb_memeql(tvb, offset, (const guint8 *)REQUEST_STR, sizeof(REQUEST_STR) - 1)) 
    {
		
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
*/

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
        "HDFSDATA2 Protocol", /* name       */
        "HDFSDATA2",      /* short name */
        "hdfsdata2"       /* abbrev     */
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

    register_dissector("hdfsdata2", dissect_hadoop, proto_hadoop);
}

void proto_reg_handoff_hadoop(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t hadoop_handle;

    if (!initialized) 
    {
        hadoop_handle = find_dissector("hdfsdata2");
        dissector_add_handle("tcp.port", hadoop_handle);  /* for "decode as" */
        initialized = TRUE;
    } 
}

