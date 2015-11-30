package cn.seed.pcap.parser.usefulStructure;

import cn.seed.pcap.parser.protocol.RTCP;

public class RTCPStructure {
	private RTCP rtcpdata = null;
	private long orilen = -1;
	private long time = -1;
	
	public RTCPStructure(RTCP rtcpdata, long orilen, long time){
		this.rtcpdata = rtcpdata;
		this.orilen = orilen;
		this.time = time;
	}
	
	public RTCP getRTCPData(){
		return this.rtcpdata;
	}
	
	public long getTime(){
		return this.time;
	}
	
	public long getLength(){
		return this.orilen;
	}
}
