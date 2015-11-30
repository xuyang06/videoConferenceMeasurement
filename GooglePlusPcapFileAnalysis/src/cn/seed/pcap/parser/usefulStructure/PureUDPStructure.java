package cn.seed.pcap.parser.usefulStructure;

import cn.seed.pcap.parser.protocol.RTP;

public class PureUDPStructure {
	private byte[] pureUDPData = null;
	private long orilen = -1;
	private long time = -1;
	private int ipID = -1;
	
	public PureUDPStructure(byte[] pureUDPData, long orilen, long time, int ipID){
		this.pureUDPData = pureUDPData;
		this.orilen = orilen;
		this.time = time;
		this.ipID = ipID;
	}
	
	public byte[] getPureUDPData(){
		return this.pureUDPData;
	}
	
	public long getTime(){
		return this.time;
	}
	
	public long getLength(){
		return this.orilen;
	}
	
	public int getIPID(){
		return this.ipID;
	}
}
