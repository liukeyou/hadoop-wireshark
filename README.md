hadoop-wireshark
================

wireshark plugin for hadoop 2.x(hdfs/yarn/hbase)

# Introduction
hadoop-wireshark is a open source hadoop 2.x protocol analyzer plugin with Wireshark. The hadoop rpc packet dissect according to [HadoopRpc](http://wiki.apache.org/hadoop/HadoopRpc). Some protobuf handles code copy from [protobuf-wireshark](http://code.google.com/p/protobuf-wireshark/).

# Feature
1. Hadoop(cloudera 5.x) 2.2 / 2.3 / 2.4 / 2.4.1 packet dissect including HDFS/YARN/MapReduce
1. HBase(cloudera 5.x) 0.96.x / 0.98.x / packet dissect
1. authentication (support Hadoop, HBase Plan)
1. HDFS Data packet (support) 
1. Spack (Plan)

# Build and Run
## Build
1. Before build you must install vs2010 and [protobuf](https://code.google.com/p/protobuf/)
1. Download the sourcecode of current stable version [Wireshark 1.10.8](http://www.wireshark.org/download/src/wireshark-1.10.8.tar.bz2)
1. Build wireshark
1. Enter the wireshark plugins dir and mkdir "hadoop" (wireshark-1.10.8\plugins\hadoop)
1. Copy hadoop-wireshark file to hadoop dir
1. Modify the PROTOBUF_DIR and PROTOBUF_LIB variable with you dir in Makefile.nmake file
1. Open vs2010 cmd and enter hadoop dir
1. Use nmake cmd to build（nmake -f Makefile.nmake） 

## Run
1. Copy the hadoop and hbase proto file to the wireshark plugin dir(in my computer is "E:\dev\opensource\wireshark\wireshark-1.10.8\wireshark-gtk2\plugins\1.10.8\hadoop-wireshark")
1. Copy the hadoop.dll to wireshark plugin install dir (wireshark-1.10.8\wireshark-gtk2\plugins\1.10.8) 
1. Run wireshark and open packet file
1. Select one hadoop packet and right click 
1. Select "Decode as" and open Transport sheet page 
![decode as](https://github.com/liukeyou/hadoop-wireshark/blob/master/doc/decode%20as.PNG)
1. Select HADOOP 
![dissect](https://github.com/liukeyou/hadoop-wireshark/blob/master/doc/dissect.PNG)
1. Select HBASE
![dissect](https://github.com/liukeyou/hadoop-wireshark/blob/master/doc/hbasedecode.PNG)
1. Select HDFSDATA2
![dissect](https://github.com/liukeyou/hadoop-wireshark/blob/master/doc/hdfsdatadecode.PNG)

## setup
you can download the setup file:[hadoop-wireshark(1.10.8) setup file](https://github.com/liukeyou/hadoop-wireshark/blob/master/setup/Output/hadoop-wireshark.exe?raw=true)

# Change Logs
1. version 0.8.0: support hdfsdata2 & fix bug 
1. version 0.7.0: support hadoop authentication & fix bug  
1. version 0.6.0: support x86 platform
1. version 0.0.6: support wireshark-1.10.8(x64) with windows vs2010

#Known Issues
1. not support hdfs DataTransferEncryptorMessageProto
2. not support TaskUmbilicalProtocol （the use WritableRpcEngine, not use ProtobufRpcEngine） 

# Licence
hadoop-wireshark is published under the Apache V2.

# Contact
www.Xdrv.com
