package cn.seed.pcap.parser;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import cn.seed.util.FileUtil;
import cn.seed.pcap.parser.usefulStructure.*;
import cn.seed.pcap.parser.protocol.RTP;
import cn.seed.pcap.parser.protocol.RTCP;

public class PCAPSimpleParser {
	private int type;
	private List<RTPStructure> RTPStructures = new ArrayList<RTPStructure>();
	private List<RTCPStructure> RTCPStructures = new ArrayList<RTCPStructure>();
	private List<PureUDPStructure> PureUDPStructures = new ArrayList<PureUDPStructure>();
	public void parseFile(String filename, int type, String srcIP, String dstIP, int srcPort, int dstPort)
	{
		this.type = type;
		PCAPPackageParser parser = new PCAPPackageParser(filename, type, srcIP, dstIP, srcPort, dstPort);
		Package pack = parser.getNextPackage();
		
		while(pack != null)
		{	
			if ( this.type == ProtocolStackParser.RTPType ){
				RTP rtp = parser.getRTPData();
				if ( rtp != null ){
					long orilen = pack.getHeader().getOriLen();
					long time = pack.getHeader().getTime();
					RTPStructure rtpStructure = new RTPStructure(rtp, orilen, time);
					RTPStructures.add(rtpStructure);
				}
			}
			else if ( this.type == ProtocolStackParser.RTCPType){
				RTCP rtcp = parser.getRTCPData();
				if ( rtcp != null ){
					long orilen = pack.getHeader().getOriLen();
					long time = pack.getHeader().getTime();
					RTCPStructure rtcpStructure = new RTCPStructure(rtcp, orilen, time);
					RTCPStructures.add(rtcpStructure);
				}
			}
			else if ( this.type == ProtocolStackParser.PureUDPType ){
				byte[] pureUDPData = parser.getPureUDPData();
				int ipID = parser.getPureUDPIPID();
				if ( pureUDPData != null ){
					long orilen = pack.getHeader().getOriLen();
					long time = pack.getHeader().getTime();
					PureUDPStructure pureUDPStructure = new PureUDPStructure(pureUDPData, orilen, time, ipID);
					PureUDPStructures.add(pureUDPStructure);
				}
			}
			
			pack = parser.getNextPackage();
			
		}
		parser.close();
	}
	
	public List<RTPStructure> getRTPStructures(){
		return this.RTPStructures;
	}
	
	public List<RTCPStructure> getRTCPStructures(){
		return this.RTCPStructures;
	}
	
	public List<PureUDPStructure> getPureUDPStructures(){
		return this.PureUDPStructures;
	}
	
	
//	public void parseFolder(String path) throws IOException
//	{
//		File folder = new File(path);
//		String[] filenames = FileUtil.listFiles(folder);
//		for(int i=0; i<filenames.length; i++)
//		{
//			String fullname = path + "\\"+ filenames[i];
//			parseFile(fullname);
//		}
//	}
	
	
}
