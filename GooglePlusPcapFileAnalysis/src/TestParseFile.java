import cn.seed.pcap.parser.PCAPSimpleParser;
import cn.seed.pcap.parser.ProtocolStackParser;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import cn.seed.pcap.parser.protocol.*;
import cn.seed.pcap.parser.usefulStructure.*;
import cn.seed.util.*;
import cn.seed.pcap.parser.flowAnalysis.*;

public class TestParseFile {
	private String outFilePath = null;
	private String inFilePath = null;
	private int type = -1;
	private String srcIP = null;
	private String dstIP = null;
	private int srcPort = -1;
	private int dstPort = -1; 
	private long timeStart = 0;
	private long duration = 8*60*1000000;
	private long timeEnd = 0;
	private PCAPSimpleParser parser = null;
	private List<UniqueVideoFlow> uniqueVideoFlowLists = new ArrayList<UniqueVideoFlow>();
	
	
	public TestParseFile(String inFilePath, String outFilePath, int type, String srcIP, String dstIP, int srcPort, int dstPort){
		this.inFilePath = inFilePath;
		this.outFilePath = outFilePath;
		this.type = type;
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.parser = new PCAPSimpleParser();
		this.parser.parseFile(this.inFilePath, this.type, this.srcIP, this.dstIP, this.srcPort, this.dstPort);		
		
	}
	
	public int existFlowLists(int ID){
		int exist = -1;
		for(int i = 0; i < uniqueVideoFlowLists.size(); i++){
			if (uniqueVideoFlowLists.get(i).existID(ID)){
				return i;
			}
		}
		return exist;
	}
	
	public void printPureUDPInfo(){
		if (this.type == ProtocolStackParser.PureUDPType){
			List<PureUDPStructure> pureUDPStructures = this.parser.getPureUDPStructures();
			File write = new File(this.outFilePath);
			long duration = 5*60*1000000;
			int first = 1;
			long firstTime = 0;
			long lastTime = 0;
			try{
				BufferedWriter bw = new BufferedWriter(new FileWriter(write));
				for(int i = 0; i < pureUDPStructures.size(); i++){
					PureUDPStructure pureUDPStructure = pureUDPStructures.get(i);
					byte[] pureUDPData = pureUDPStructure.getPureUDPData();
					long orilen = pureUDPStructure.getLength();
					long time = pureUDPStructure.getTime();
					int udpIPID = pureUDPStructure.getIPID();
					if (first == 1){
						firstTime = time;
						lastTime = firstTime + duration;
						first = 0;
					}
					if (time > lastTime){
						break;
					}
					/*if (rtpdata.getVersion() == 2){
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC())  + "\015\012";
					String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData())
					
					}*/
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " + String.valueOf(udpIPID) + " " + ByteUtil.byte2HexStr(pureUDPData) + "\015\012";
					//String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " + String.valueOf(udpIPID) + "\015\012";
			//String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
				}
				bw.close();
			}
			catch(FileNotFoundException e){ 
				System.out.println (e);
			}
			catch(IOException e){
				System.out.println (e);
			}
		}
	}
	
	
	
	public void printRTPInfo(){
		if (this.type == ProtocolStackParser.RTPType){
			List<RTPStructure> RTPStructures = this.parser.getRTPStructures();
			File write = new File(this.outFilePath);
			try{
				BufferedWriter bw = new BufferedWriter(new FileWriter(write));
				for(int i = 0; i < RTPStructures.size(); i++){
					RTPStructure rtpStructure = RTPStructures.get(i);
					RTP rtpdata = rtpStructure.getRTPData();
					long orilen = rtpStructure.getLength();
					long time = rtpStructure.getTime();
					/*if (rtpdata.getVersion() == 2){
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC())  + "\015\012";
					String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData())
					
					}*/
					/*String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
					" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
					+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
					+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +ByteUtil.byte2HexStr(rtpdata.getCSRCBytes()) + "\015\012";*/
					
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC()) + "\015\012";
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData()) 
					//String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
				}
				bw.close();
			}
			catch(FileNotFoundException e){ 
				System.out.println (e);
			}
			catch(IOException e){
				System.out.println (e);
			}
		}
	}
	
	
	public void printRTPOneFlowInfo(String SSRCID){
		if (this.type == ProtocolStackParser.RTPType){
			List<RTPStructure> RTPStructures = this.parser.getRTPStructures();
			File write = new File(this.outFilePath);
			long lenTotal = 0;
			int first = 1;
			long timeFirst = 0;
			long timeLast = 0;
			try{
				BufferedWriter bw = new BufferedWriter(new FileWriter(write));
				for(int i = 0; i < RTPStructures.size(); i++){
					RTPStructure rtpStructure = RTPStructures.get(i);
					RTP rtpdata = rtpStructure.getRTPData();
					long orilen = rtpStructure.getLength();
					long time = rtpStructure.getTime();
					if (String.valueOf(rtpdata.getSSRC()).equalsIgnoreCase(SSRCID)){
						if (first == 1){
							first = 0;
							timeFirst = time;
							timeLast = time;
						}else{
							timeLast = time;
						}
						lenTotal += orilen;
					/*if (rtpdata.getVersion() == 2){
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC())  + "\015\012";
					String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData())
					
					}*/
					/*String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
					" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
					+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
					+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +ByteUtil.byte2HexStr(rtpdata.getCSRCBytes()) + "\015\012";*/
					
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC()) + "\015\012";
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData()) 
					//String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
					}
				}
				float rate = (float)lenTotal / (float)((timeLast - timeFirst)/1000000.0);
				System.out.println("The rate is " + rate + "\015\012");
				bw.close();
			}
			catch(FileNotFoundException e){ 
				System.out.println (e);
			}
			catch(IOException e){
				System.out.println (e);
			}
		}
	}
	
	
	
	
	public void printRTPFlowInfo(String SSRCNum){
		if (this.type == ProtocolStackParser.RTPType){
			List<RTPStructure> RTPStructures = this.parser.getRTPStructures();
			File write = new File(this.outFilePath);
			try{
				BufferedWriter bw = new BufferedWriter(new FileWriter(write));
				for(int i = 0; i < RTPStructures.size(); i++){
					RTPStructure rtpStructure = RTPStructures.get(i);
					RTP rtpdata = rtpStructure.getRTPData();
					long orilen = rtpStructure.getLength();
					long time = rtpStructure.getTime();
					/*if (rtpdata.getVersion() == 2){
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtpdata.getVersion()) + 
							" " +String.valueOf(rtpdata.getPadding()) + " " +String.valueOf(rtpdata.getExtension()) + " " +String.valueOf(rtpdata.getCSRCcount()) + " " +String.valueOf(rtpdata.getMarker())
							+ " " +String.valueOf(rtpdata.getPayloadType()) + " " +String.valueOf(rtpdata.getSequenceNumber()) 
							+ " " +String.valueOf(rtpdata.getTimestamp()) + " " +String.valueOf(rtpdata.getSSRC()) + " " +String.valueOf(rtpdata.getCSRC())  + "\015\012";
					String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";
					bw.write(writeLineString);
					//+ " " + ByteUtil.byte2HexStr(rtpdata.getRTPData())
					
					}*/
					if (String.valueOf(rtpdata.getSSRC()).equalsIgnoreCase(SSRCNum)){
						int CSRCID = rtpdata.getCSRCLowID();
						int index = existFlowLists(CSRCID);
						if ( index == -1 ){
							UniqueVideoFlow videoFlow = new UniqueVideoFlow(CSRCID, orilen, time);
							uniqueVideoFlowLists.add(videoFlow);
						}else{
							uniqueVideoFlowLists.get(index).addLen(CSRCID, orilen, time);
						}
					}
					
			//String writeLineString = String.valueOf(rtpdata.getTimestamp()) + "\015\012";					
				}
				for (int i = 0; i < uniqueVideoFlowLists.size(); i++){
					String line1 = "For ID " + uniqueVideoFlowLists.get(i).getUniqueID() + ":\015\012";
					String line2 = "Total Count = " + uniqueVideoFlowLists.get(i).getTotalCount() + ";\015\012";
					String line3 = "Total Rate = " + uniqueVideoFlowLists.get(i).getVideoFlowRate() + "Bytes/s. \015\012";
					bw.write(line1);
					bw.write(line2);
					bw.write(line3);
				}
				bw.close();
			}
			catch(FileNotFoundException e){ 
				System.out.println (e);
			}
			catch(IOException e){
				System.out.println (e);
			}
		}
	}
	
	
	public void printRTCPInfo(){
		if (this.type == ProtocolStackParser.RTCPType){
			List<RTCPStructure> RTCPStructures = this.parser.getRTCPStructures();
			File write = new File(this.outFilePath);
			try{
				BufferedWriter bw = new BufferedWriter(new FileWriter(write));
				for(int i = 0; i < RTCPStructures.size(); i++){
					RTCPStructure rtcpStructure = RTCPStructures.get(i);
					RTCP rtcpdata = rtcpStructure.getRTCPData();
					long orilen = rtcpStructure.getLength();
					long time = rtcpStructure.getTime();
					String writeLineString = String.valueOf(time) + " " + String.valueOf(orilen) + " " +String.valueOf(rtcpdata.getVersion()) + 
							" " +String.valueOf(rtcpdata.getPadding()) + " " +String.valueOf(rtcpdata.getReceptionReportCount()) + " " +String.valueOf(rtcpdata.getType())
							+ " " +String.valueOf(rtcpdata.getRTCPdatalength()) + " " +ByteUtil.byte2HexStr(rtcpdata.getRTCPData()) + "\015\012";
					bw.write(writeLineString);
				}
				bw.close();
			}
			catch(FileNotFoundException e){ 
				System.out.println (e);
			}
			catch(IOException e){
				System.out.println (e);
			}
		}
	}
	
	public static void main(String[] args)
	{
		//String inFilePath = "D:\\Research\\video_conference\\googleplusNew\\test\\download_lost002_feng.pcap";
		//String outFilePath = "D:\\Research\\video_conference\\googleplusNew\\test\\download_lost002_fengVideoOutput.txt";
		//String inFilePath = "D:\\Research\\video_conference\\google\\google+_11_28\\download_0_500_feng.pcap";
		//String outFilePath = "D:\\Research\\video_conference\\google\\resultnew\\download_0_500_feng2.txt";
		//String inFilePath = "D:\\Research\\video_conference\\ichat\\1_3\\yucg_1view_download010.pcap";
		/*String inFilePath = "D:\\Research\\video_conference\\ichat\\1_3\\router_1view_upload010.pcap";
		String outFilePath = "D:\\Research\\video_conference\\ichat\\1_3\\result\\router_1view_upload010.txt";
		int type = ProtocolStackParser.RTPType;
		//String srcIP = "192.168.1.9"; 
		//String dstIP = "74.125.115.127";
		//int srcPort = 58843;
		//int dstPort = 19305;
		String srcIP = "128.238.35.187"; 
		String dstIP = "128.238.35.133";
		int srcPort = 62498;
		int dstPort = 54618;
		String SSRCNum = "2614010707";
		TestParseFile testParse = new TestParseFile(inFilePath, outFilePath, type, srcIP, dstIP, srcPort, dstPort);
		testParse.printRTPInfo();*/
		//testParse.printRTPFlowInfo(SSRCNum);
		
		
		/*String inFilePath = "D:\\Research\\video_conference\\google\\google+ 11_26\\normal_chenguang.pcap";
		String outFilePath = "D:\\Research\\video_conference\\google\\google+ 11_26\\result\\download0_chenguang_receiver_voice.txt";
		//int type = ProtocolStackParser.PureUDPType;
		int type = ProtocolStackParser.RTPType;
		//String srcIP = "192.168.1.9"; 
		//String dstIP = "74.125.115.127";
		//int srcPort = 58843;
		//int dstPort = 19305;
		String srcIP = "74.125.115.127"; 
		String dstIP = "192.168.137.171";
		int srcPort = 19305;
		int dstPort = 58754;
		String SSRCNum = "2614010707";
		TestParseFile testParse = new TestParseFile(inFilePath, outFilePath, type, srcIP, dstIP, srcPort, dstPort);
		testParse.printRTPInfo();*/
		
		
		String inFilePath = "D:\\delayVideo\\google_normal-receiver.pcap";
		//String outFilePath = "D:\\Research\\video_conference\\google\\google+ 11_26\\result\\google+_download5_xu_receiver_voice.txt";
		String outFilePath = "D:\\delayVideo\\google_normal_receiver_video.txt";
		//String inFilePath d= "D:\\Research\\video_conference\\ichat\\1_3\\feng_1view_download002.pcap";
		//String outFilePath = "D:\\Research\\video_conference\\ichat\\1_3\\lossresult\\feng_1view_download002_receiver_62498.txt";
		
		//String outFilePath = "D:\\Research\\video_conference\\1_13\\skype_normal_tan_receiver.txt";
		//int type = ProtocolStackParser.PureUDPType;
		int type = ProtocolStackParser.RTPType;
		//String srcIP = "192.168.1.9"; 
		//String dstIP = "74.125.115.127";
		//int srcPort = 58843;
		//int dstPort = 19305;
		//String srcIP = "192.168.1.11"; 
		//String dstIP = "128.238.35.187";
		//String srcIP = "192.168.137.117"; 
		
		//String srcIP = "192.168.137.117";
		//String srcIP = "128.238.35.187";
		//String dstIP = "74.125.91.127";
		
		String srcIP = "173.194.76.127";
		//String srcIP = "74.125.91.127";
		
		//String dstIP = "192.168.1.22";
		//String dstIP = "192.168.137.203";
		String dstIP = "192.168.1.4";
		
		//String dstIP = "128.238.35.133";
		//int srcPort = 52512;
		//int srcPort = 16402;
		int srcPort = 19305;
		int dstPort = 62156;
		//int srcPort = 19305;
		//int dstPort = 62301;
		//int dstPort = 53821;
		
		//int dstPort = 54618;
		/*String srcIP = "208.88.186.107";
		String dstIP = "192.168.1.8";
		//String dstIP = "128.238.35.133";
		int srcPort = 8192;
		//int srcPort = 16402;
		int dstPort = 56172;
		*/
		/*String srcIP = "128.238.35.133";
		//String dstIP = "74.125.91.127";
		String dstIP = "192.168.137.117";
		//int srcPort = 52512;
		//int srcPort = 16402;
		int srcPort = 58966;
		//int dstPort = 19305;
		int dstPort = 16402;
		//int dstPort = 62498;
		String SSRCNum = "33554432";*/
		TestParseFile testParse = new TestParseFile(inFilePath, outFilePath, type, srcIP, dstIP, srcPort, dstPort);
		testParse.printRTPInfo();
		//testParse.printPureUDPInfo();
		//testParse.printRTPOneFlowInfo(SSRCNum);
		
	}
}
