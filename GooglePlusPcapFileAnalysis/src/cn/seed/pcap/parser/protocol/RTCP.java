package cn.seed.pcap.parser.protocol;

public class RTCP {
	private int version = -1;
	private int padding = -1;
	private int receptionReportCount = -1;
	private int type = -1;
	private int length = -1;
	private int RTCPdatalength = -1;
	private int start;
	private byte[] raw_data;
	private byte[] RTCP_data = null;
	private int dataStart;
	
	public RTCP(byte[] aRaw_data, int aStart)
	{
		this.raw_data = aRaw_data;
		this.start = aStart;
	}
	
	public int getVersion()
	{
		if(this.version == -1)
		{
			version = ( (int) ( raw_data[start] >> 6)) & 0x03;
		}
		
		return this.version;
	}
	
	public int getPadding()
	{
		if(this.padding == -1)
		{
			padding = ( (int) ( raw_data[start] >> 5)) & 0x01;
		}
		
		return this.padding;
	}
	
	public int getReceptionReportCount()
	{
		if(this.receptionReportCount == -1)
		{
			receptionReportCount = ( (int) ( raw_data[start] )) & 0x1F;
		}
		
		return this.receptionReportCount;
	}
	
	public int getType()
	{
		if(this.type == -1)
		{
			type = ( (int) ( raw_data[start+1] )) & 0xFF;
		}
		
		return this.type;
	}
	
	public int getLength()
	{
		if(this.length == -1)
		{
			byte low = raw_data[start+3];
			byte high = raw_data[start+2];
			length = (int)low & 0xFF;
			length |= ((int)high << 8) & 0xFF00;
			length = ( length + 1 ) * 4;
		}
		
		return this.length;
	}
	
	public int getRTCPdatalength(){
		if(this.RTCPdatalength == -1){
			this.RTCPdatalength = raw_data.length - 4;
			this.dataStart = this.start + 4;
		}
		return this.RTCPdatalength;
	}
	
	public byte[] getRTCPData(){
		if (this.RTCP_data == null){
			int datalength = getRTCPdatalength();
			if(datalength != 0 )
			{
				try{
					RTCP_data = new byte[datalength];
					System.arraycopy(raw_data, this.dataStart, RTCP_data, 0, datalength);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
		}
		return this.RTCP_data;
	}
}
