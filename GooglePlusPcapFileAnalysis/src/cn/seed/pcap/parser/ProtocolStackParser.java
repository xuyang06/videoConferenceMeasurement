package cn.seed.pcap.parser;

import java.util.Arrays;

import cn.seed.pcap.parser.protocol.Ethernet2;
import cn.seed.pcap.parser.protocol.IP;
import cn.seed.pcap.parser.protocol.TCP;
import cn.seed.pcap.parser.protocol.UDP;
import cn.seed.pcap.parser.protocol.RTP;
import cn.seed.pcap.parser.protocol.RTCP;
import cn.seed.util.*;

public class ProtocolStackParser {
	
	private Ethernet2 ethData = null;
	private IP ipv4Data = null;
	private TCP tcpData = null;
	private UDP udpData = null;
	private RTP rtpData = null;
	private RTCP rtcpData = null;
	private byte[] pureUDPData = null;
	private int type = -1;
	private int ipID = -1;
	public static final int RTPType = 1;
	public static final int RTCPType = 2;
	public static final int OtherType = 3;
	public static final int PureUDPType = 4;
	private String srcIP = null;
	private String dstIP = null;
	private int srcPort = -1;
	private int dstPort = -1;
	
	public ProtocolStackParser(Package pack, int start, int type, String srcIP, String dstIP, int srcPort, int dstPort)
	{
		
		byte[] raw_data = pack.getData().getRawData();
		this.type = type;
		this.ethData = new Ethernet2(raw_data, start);
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		
		
		if(this.ethData.getMacDataType() == Ethernet2.IPv4)
		{
			this.ipv4Data = new IP(raw_data, this.ethData.getDataStart());
			if (this.ipv4Data.getSrcAddr().equalsIgnoreCase(this.srcIP) && this.ipv4Data.getDestAddr().equalsIgnoreCase(this.dstIP)){
				
			
//			System.out.println(ipv4.getDataType());
//			System.out.println(ipv4.getDestAddr());
//			System.out.println(ipv4.getHeaderLength());
//			System.out.println(ipv4.getSrcAddr());
//			System.out.println(ipv4.getTotalLength());
//			System.out.println("ok");
			
				if(this.ipv4Data.getDataType() == IP.UDP )
				{
					this.udpData = new UDP(raw_data, this.ipv4Data.getStart() + this.ipv4Data.getHeaderLength());
					if ( (this.udpData.getSourcePort() == this.srcPort) && (this.udpData.getDestPort() == this.dstPort)){
						if (type == this.RTPType){
							
							byte[] udpPureData = udpData.getUDPData();
							//System.out.println(ByteUtil.byte2HexStr(udpPureData) + "\n");
							if ( udpPureData != null){
								this.rtpData = new RTP(udpPureData, 0);
							}
						}
						else if (type == this.RTCPType){
							byte[] udpPureData = udpData.getUDPData();
							if ( udpPureData != null){
								this.rtcpData = new RTCP(udpPureData, 0);
							}
						}
						else if (type == this.PureUDPType){
							this.ipID = this.ipv4Data.getIdentificationInteger();
							this.pureUDPData = udpData.getUDPData();
						}
					}
					//²âÊÔ½á¹û
	//				for(int i=udp.getStart(); i<raw_data.length; i++)
	//				{
	//					System.out.print(ByteUtil.byte2HexStr(raw_data[i]) + " ");
	//				}
					
	//				System.out.println("");
	//				System.out.println(udp.getSourcePort());
	//				System.out.println(udp.getDestPort());
	//				System.out.println(udp.getLength());
	//				System.out.println(udp.getDataLength());
	//				System.out.println(udp.getDataStart());
	//				System.out.println("ok");
					
				}
				else if(this.ipv4Data.getDataType() == IP.TCP)
				{
					
					this.tcpData = new TCP(raw_data, this.ipv4Data.getStart() + this.ipv4Data.getHeaderLength(), this.ipv4Data.getTotalLength()-this.ipv4Data.getHeaderLength());
					
				}
			}
			
			
		}
		
	}
	
	public RTP getRTPData(){
		return this.rtpData;
	}
	
	public RTCP getRTCPData(){
		return this.rtcpData;
	}

	public byte[] getPureUDPData(){
		return this.pureUDPData;
	}
	
	public int getPureUDPDataIPID(){
		return this.ipID;
	}
}
