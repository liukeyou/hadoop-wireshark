/* packet-hdfsdata2.cpp
  * Routines for hadoop packet dissection
  * Copyright 2014 Liu Keyou <liukeyou@gmail.com>
  *
 */

#include "packet-hdfsdata2.h"

#define REQUEST_STR "hrpc"

static int proto_hadoop = -1;
static gint ett_hadoop = -1;

static int hf_checksums = -1;
static int hf_checksum = -1;
static int hf_data = -1;
static int hf_chunk = -1;

extern map<string, Handles*>    g_mapHandles;
extern map<string, MethodInfo>  g_mapMethod;
map<CallInfo, string>           g_mapCallInfo;
list<DataPacket>                g_listDataPacket;

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
        		 
        		 DataPacket dp;
				 dp.srcPort  = pinfo->srcport;
				 dp.destPort = pinfo->destport;
				 dp.nxtseq   = ti->nxtseq;

        		 if ( g_listDataPacket.end() == find(g_listDataPacket.begin(), g_listDataPacket.end(), dp ) )
                 {
					 g_listDataPacket.push_back(dp);
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
    // get payload lentch
    guint payloadLen = tvb_get_ntohl(tvb, *offset);
    *offset += 4;
    
    // get hearder lentch
    guint16 hearderLen = tvb_get_ntohs(tvb, *offset);
    
    if ( !dissect_protobuf_by_name("hadoop.hdfs.PacketHeaderProto", tvb, offset, hadoop_tree, string("hadoop.hdfs.PacketHeaderProto"), false, 2) )
    {
        return false;
    }
    
    if ( tvb_reported_length(tvb) != payloadLen + hearderLen + 2 )
    {
        return false;
    }
    
    int dataPlusChecksumLen = payloadLen - 2; //2 = Ints.BYTES;
    int32 dataLen = get_field_Int32("hadoop.hdfs.PacketHeaderProto", "dataLen", tvb, 4, false, 2);
    int32 checksumLen = dataPlusChecksumLen - dataLen;
    
    proto_item* itemChecksum = proto_tree_add_none_format( hadoop_tree, hf_checksums, tvb, *offset, checksumLen, "%s", "checksums" );
    proto_tree* subTreeChecksum = proto_item_add_subtree( itemChecksum, ett_hadoop );
    for (int32 i=0; i<checksumLen/4; i++)
    {
        proto_tree_add_uint( subTreeChecksum, hf_checksum, tvb, *offset, 4,  tvb_get_ntohl(tvb, *offset));
        *offset += 4;
    }
    
    //*offset =     
    proto_item* itemData = proto_tree_add_none_format( hadoop_tree, hf_data, tvb, *offset, dataLen, "%s", "data" );
    proto_tree* subTreeData = proto_item_add_subtree( itemData, ett_hadoop );     
    for (int32 i=0; i<checksumLen/512; i++)
    {
        proto_tree_add_item( subTreeData, hf_chunk, tvb, *offset, 512, true);
        *offset += 512;
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
            guint dataLen = tvb_get_ntohl(tvb, 0);
            if (dataLen < length)
            {
                if(dissect_write_block(tvb, &offset, hadoop_tree))
                {
                    return;    
                }
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
        if ( pinfo->private_data != NULL)
        {
            tcpinfo *ti = (tcpinfo *)(pinfo->private_data);

			DataPacket dp;
			dp.srcPort  = pinfo->srcport;
			dp.destPort = pinfo->destport;
			dp.nxtseq   = ti->seq;
			
			if ( g_listDataPacket.end() != find(g_listDataPacket.begin(), g_listDataPacket.end(), dp ) )
			{
				//int32 len = get_field_Int32("hadoop.hdfs.PacketHeaderProto", "dataLen", tvb, 4, false, 2);
				guint dataLen = tvb_get_ntohl(tvb, 0);
			    guint16 hearderLen = tvb_get_ntohs(tvb, 4);
			    if ( dataLen+hearderLen+2 > packetLen )
			    {
			        return dataLen+hearderLen+2;
			    }
			}
		}
    }

    return tvb_reported_length(tvb);
}

static void dissect_hadoop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int packetLen = 0;
    gboolean need_reassemble = FALSE;
    guint offset  = 0;

    packetLen = tvb_reported_length(tvb);
    
	// maybe data
    if (packetLen >= 31)
    {
        if ( pinfo->private_data != NULL)
        {
            tcpinfo *ti = (tcpinfo *)(pinfo->private_data);

			DataPacket dp;
			dp.srcPort  = pinfo->srcport;
			dp.destPort = pinfo->destport;
			dp.nxtseq   = ti->seq;
			
			if ( g_listDataPacket.end() != find(g_listDataPacket.begin(), g_listDataPacket.end(), dp ) )
			{
				/*
				int32 len = get_field_Int32("hadoop.hdfs.PacketHeaderProto", "dataLen", tvb, 4, false, 2);
				if (len > frame_header_len)
				{
					need_reassemble = true;
				}
				*/
				guint dataLen = tvb_get_ntohl(tvb, 0);
			    guint16 hearderLen = tvb_get_ntohs(tvb, 4);
			    if ( dataLen+hearderLen+2 > packetLen )
			    {
			        need_reassemble = true;
			    }	
			}
		}
    }

    tcp_dissect_pdus(tvb, pinfo, tree, need_reassemble, packetLen, get_hadoop_message_len, dissect_hadoop_message);
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
        { &hf_checksums,
          { "HDFS Checksums", "hdfs.checksums",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data,
          { "HDFS DATA", "hdfs.data",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_checksum,
          { "HDFS checksum", "hdfs.checksum",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_chunk,
          { "HDFS chunk", "hdfs.chunk",
            FT_NONE, BASE_NONE,
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

