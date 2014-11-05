#include "protobuf-handle.h"

map<string, Handles*>   g_mapHandles;
map<string, MethodInfo> g_mapMethod;
list<string>            g_listPBFile;   

void register_protobuf_field(const FieldDescriptor* field, int proto_hadoop)
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

void register_protobuf_message(const Descriptor* message, int proto_hadoop)
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
		register_protobuf_message(nestMessage, proto_hadoop);
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
        register_protobuf_field(fieldDescriptor, proto_hadoop);
    }

}

void register_protobuf_file(string filePath, string fileName, int proto_hadoop)
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

        register_protobuf_file(filePath, dependencyFile->name(), proto_hadoop);
    }
    
    // parse message
    for (int iMsgIndex = 0; iMsgIndex < file->message_type_count(); iMsgIndex++)
    {
        const Descriptor* message = file->message_type(iMsgIndex);
        register_protobuf_message(message, proto_hadoop);
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

void register_protobuf_files(string& pbFilePath, int proto_hadoop)
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
                    register_protobuf_file (pbFilePath, ent->d_name, proto_hadoop);
                    break;
                case DT_DIR:
                      filePath = pbFilePath + "/" + ent->d_name;
                    register_protobuf_files (filePath, proto_hadoop);
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
    return true;
}

bool dissect_protobuf_message(const Message* message, tvbuff_t *tvb, guint* offset, proto_tree *tree, string& displayText, bool bRoot)
{
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

bool protobuf_get_message(const string msgName, tvbuff_t *tvb, guint* offset, bool bVarintLen, guint16 lenByte, Message **messagePacket)
{
    // get message handles
    map<string, Handles*>::iterator it = g_mapHandles.find( msgName );
    if( it == g_mapHandles.end() ) 
    {
        return false; // bug
    }
    
    Handles* handles = it->second;
    
    // get message len
    guint len = 0;
    if (bVarintLen)
    {
        if (!read_varint32(tvb, offset, &len)) 
        {
            return false;
        }
    } else {
        if (lenByte == 4)
        {
            len = tvb_get_ntohl(tvb, *offset);
	        *offset += 4;
	    } else {
	        len = tvb_get_ntohs(tvb, *offset);
	        *offset += 2;
	    }
    }
    
    if (len > tvb_reported_length(tvb))
    {
        return false;
    }
    // get message buffer
    const guint8* buf = tvb_get_ptr(tvb, *offset, len);
    
    DynamicMessageFactory *factory = new DynamicMessageFactory();
    const Message *message = NULL;
    message = factory->GetPrototype(handles->descriptor);
    *messagePacket = message->New();
    
    return (*messagePacket)->ParseFromArray(buf, len);  
}

bool dissect_protobuf_by_name(const string msgName, tvbuff_t *tvb, guint* offset, proto_tree *tree, string& displayText, bool bVarintLen, guint16 lenByte)
{
    guint oldOffset = *offset;
    
    Message *messagePacket = NULL;
    if( protobuf_get_message(msgName, tvb, offset, bVarintLen, lenByte, &messagePacket) )
    {
        return dissect_protobuf_message(messagePacket, tvb, offset, tree, displayText, true);
    }
    
    *offset = oldOffset;
    return false;
}

int32 get_field_Int32(const string& msgName, const string& fieldName, tvbuff_t *tvb, guint offset, bool bVarintLen, guint16 lenByte)
{   
    Message *messagePacket = NULL;
    if( protobuf_get_message(msgName, tvb, &offset, bVarintLen, lenByte, &messagePacket) )
    {
        const Reflection *reflection = messagePacket->GetReflection();
        vector<const FieldDescriptor*> fieldList;
        reflection->ListFields(*messagePacket, &fieldList);
        for( vector<const FieldDescriptor*>::iterator itField = fieldList.begin(); itField!=fieldList.end(); itField++ )
        {
            const FieldDescriptor* field = *itField;
            bool bMessage = ( FieldDescriptor::CPPTYPE_MESSAGE == field->cpp_type() );
                
            if (!bMessage)
            {
                if (0 == field->name().compare(fieldName))
                {
                    return reflection->GetInt32( *messagePacket, field );
                }
            }
        }
    }
    
    return 0;
}