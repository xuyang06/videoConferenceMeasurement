package cn.seed.pcap.parser;

import cn.seed.util.ByteUtil;



public class PackageHeader {
	private byte[] rawHeader = null;
	private int start = 0;
	private long capLen = -1;
	private long orilen = -1;
	private long time = -1;
	
	public void setRawHeader(byte[] aRawHeader){
		this.rawHeader = aRawHeader;
	}
	
	public long getTime()
	{
		if(this.time == -1)
		{
			long high = ByteUtil.pcapBytesToLong(rawHeader, start); //seconds
			long low = ByteUtil.pcapBytesToLong(rawHeader, start+4); // microseconds
			/*high = high*1000;
			//low = 0;
			low = low/1000;*/
			high = high*1000000;
			//low = 0;
			low = low;
			this.time = high + low;
		}
		return time;
	}
	
	public long getCapLen()
	{
		
		if(capLen == -1)
		{
			this.capLen = ByteUtil.pcapBytesToLong(rawHeader, start + 8);
		}
		return capLen;
	}
	
	public long getOriLen()
	{
		if(orilen == -1)
		{
			this.orilen = ByteUtil.pcapBytesToLong(rawHeader, start + 12);
			
		}
		return orilen;
	}
}
