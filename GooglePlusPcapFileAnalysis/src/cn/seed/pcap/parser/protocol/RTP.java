package cn.seed.pcap.parser.protocol;

import java.util.Arrays;

import cn.seed.util.ByteUtil;

public class RTP {
	private int version = -1;
	private int padding = -1;
	private int extension = -1;
	private int CSRCcount = -1;
	private int Marker = -1;
	private int PayloadType = -1;
	private int SequenceNumber = -1;
	private long Timestamp = -1;
	private long SSRC = -1;
	private long CSRC = -1;
	
	private int start;
	private int dataStart;
	private byte[] raw_data;
	private byte[] RTPData = null;
	private int dataLength = -1;
//	private int getStart()
//	{
//		return this.start;
//	}
	public RTP(byte[] raw_data, int start)
	{
		this.raw_data = raw_data;
		this.start = start;
	}
	
	
	public int getDataLength()
	{
		if (dataLength == -1){
			this.dataLength = raw_data.length - 16;
			this.dataStart = this.start + 16;
			
		}
		return this.dataLength;
	}
	
	//
	public byte[] getRTPData(){
		if (this.RTPData == null){
			getDataLength();
			if(this.dataLength != 0 )
			{
				//System.out.println("data length is" + dataLength + ", dataStart is" + this.dataStart + "\n");
				//System.out.println(ByteUtil.byte2HexStr(raw_data) + "\n");
				try{
					RTPData = new byte[dataLength];
					System.arraycopy(raw_data, this.dataStart, RTPData, 0, dataLength);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
		}
		return this.RTPData;
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
	
	public int getExtension()
	{
		if(this.extension == -1)
		{
			extension = ( (int) ( raw_data[start] >> 4)) & 0x01;
		}
		
		return this.extension;
	}
	
	public int getCSRCcount()
	{
		if(this.CSRCcount == -1)
		{
			CSRCcount = ( (int) ( raw_data[start] )) & 0x0F;
		}
		
		return this.CSRCcount;
	}
	
	public int getMarker()
	{
		if(this.Marker == -1)
		{
			Marker = ( (int) ( raw_data[start+1] >> 7 )) & 0x01;
		}
		
		return this.Marker;
	}
	
	public int getPayloadType()
	{
		if(this.PayloadType == -1)
		{
			PayloadType = ( (int) ( raw_data[start+1] )) & 0x7F;
		}
		
		return this.PayloadType;
	}
	
	public int getSequenceNumber()
	{
		if(this.SequenceNumber == -1)
		{
			byte low = raw_data[start+3];
			byte high = raw_data[start+2];
			SequenceNumber = (int)low & 0xFF;
			SequenceNumber |= ((int)high << 8) & 0xFF00;
		}
		
		return this.SequenceNumber;
	}
	
	public long getTimestamp()
	{
		if(this.Timestamp == -1)
		{
			byte [] TimestampBytes = new byte [4];
			TimestampBytes[0] = raw_data[start+7];
			TimestampBytes[1] = raw_data[start+6];
			TimestampBytes[2] = raw_data[start+5];
			TimestampBytes[3] = raw_data[start+4];
			this.Timestamp = ByteUtil.unsigned4BytesToLong_high(TimestampBytes);
		}
		
		return this.Timestamp;
	}
	
	public long getSSRC()
	{
		if(this.SSRC == -1)
		{
			byte [] SSRCBytes = new byte [4];
			SSRCBytes[0] = raw_data[start+11];
			SSRCBytes[1] = raw_data[start+10];
			SSRCBytes[2] = raw_data[start+9];
			SSRCBytes[3] = raw_data[start+8];
			this.SSRC = ByteUtil.unsigned4BytesToLong(SSRCBytes);
		}
		
		return this.SSRC;
	}
	
	public long getCSRC()
	{
		if(this.CSRC == -1)
		{
			byte [] CSRCBytes = new byte [4];
			CSRCBytes[0] = raw_data[start+15];
			CSRCBytes[1] = raw_data[start+14];
			CSRCBytes[2] = raw_data[start+13];
			CSRCBytes[3] = raw_data[start+12];
			this.CSRC = ByteUtil.unsigned4BytesToLong(CSRCBytes);
		}
		
		return this.CSRC;
	}
	
	public byte[] getCSRCBytes()
	{
		byte [] CSRCBytes = new byte [4];
		CSRCBytes[0] = raw_data[start+12];
		CSRCBytes[1] = raw_data[start+13];
		CSRCBytes[2] = raw_data[start+14];
		CSRCBytes[3] = raw_data[start+15];
		return CSRCBytes;
	}
	
	public int getCSRCLowID()
	{
		byte b = raw_data[start+12];
		int lowID = ByteUtil.oneByte2Int(b);
		return lowID;
	} 

}
