package cn.seed.pcap.parser.usefulStructure;
import cn.seed.pcap.parser.protocol.RTP;


public class RTPStructure {
	private RTP rtpdata = null;
	private long orilen = -1;
	private long time = -1;
	
	public RTPStructure(RTP rtpdata, long orilen, long time){
		this.rtpdata = rtpdata;
		this.orilen = orilen;
		this.time = time;
	}
	
	public RTP getRTPData(){
		return this.rtpdata;
	}
	
	public long getTime(){
		return this.time;
	}
	
	public long getLength(){
		return this.orilen;
	}

}
