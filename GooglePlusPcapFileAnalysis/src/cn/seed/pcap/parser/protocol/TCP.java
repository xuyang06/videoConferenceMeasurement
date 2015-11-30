package cn.seed.pcap.parser.protocol;

import cn.seed.util.ByteUtil;


//Unlike UDP, the length of TCP is not constant 
public class TCP {
	private int source_port = -1;
	private int dest_port = -1;
	private int sequenceNum = -1;
	private int ackNum = -1;
	private int headerLength = -1;
	private int dataLength = -1;
	private byte flag;
	private int windowSize = -1;
	private byte checksum[] = null;
	private int dataStart = -1;
	private int tcp_len = -1;
	private int start;
	private byte[] raw_data;
	private byte[] options = null;
	private byte[] tcpData = null;
	public int getStart()
	{
		return this.start;
	}
	public TCP(byte[] raw_data, int start, int tcp_len)
	{
		this.raw_data = raw_data;
		this.start = start;
		this.tcp_len = tcp_len;
	}
	
	public int getDataLength()
	{
		if(this.dataLength == -1)
		{
			this.getDataStart();
			this.dataLength = tcp_len - this.headerLength;
//			if(this.dataLength < 0)
//				this.dataLength = 0;
		}
		return this.dataLength;
	}
	
	public int getDataStart()
	{
		if(dataStart == -1)
		{
			getHeaderLength();
			dataStart = start + this.headerLength;
			if(dataStart > this.raw_data.length)
				dataStart = raw_data.length-1;
		}
		return dataStart;
	}

	
	public int getHeaderLength()
	{
		if(this.headerLength == -1)
		{
			byte len = raw_data[start+12];
			headerLength = (int)len & 0xFF;
			headerLength = ((int)headerLength >> 4) & 0x0F;
			headerLength = headerLength*4;
		}
		return this.headerLength;
	}
	
	public int getSequenceNumber()
	{
		if(this.sequenceNum == -1)
		{
			byte[] b = new byte[4];
			b[0] = raw_data[start+4];
			b[1] = raw_data[start+5];
			b[2] = raw_data[start+6];
			b[3] = raw_data[start+7];
			this.sequenceNum = (int)ByteUtil.pcapBytesToLong(b, 0);
		}
		return this.sequenceNum;
	}
	public int getAckNumber()
	{
		if(this.ackNum == -1)
		{
			byte[] b = new byte[4];
			b[0] = raw_data[start + 8];
			b[1] = raw_data[start + 9];
			b[2] = raw_data[start + 10];
			b[3] = raw_data[start + 11];
			this.sequenceNum = (int)ByteUtil.pcapBytesToLong(b, 0);
		}
		return this.ackNum;
	}
	public byte getFlags()
	{
		return raw_data[start + 13];
	}
	public int getWindowSize()
	{
		if(this.windowSize == -1)
		{
			windowSize = raw_data[start+15] & 0xFF;
			windowSize |= ((raw_data[start+14] << 8) & 0xFF00);
		}
		return this.windowSize;
	}
	public byte[] getChecksum()
	{
		if(this.checksum == null)
		{
			checksum = new byte[2];
			checksum[0] = raw_data[start + 16];
			checksum[1] = raw_data[start + 17];
		}
		return this.checksum;
	}
	public int getSourcePort()
	{
		if(this.source_port == -1)
		{
			source_port = raw_data[start+1] & 0xFF;
			source_port |= ((raw_data[start] << 8) & 0xFF00);
		}
		return source_port;
	}
	public int getDestPort()
	{
		if(this.dest_port == -1)
		{
			dest_port = raw_data[start+3] & 0xFF;
			dest_port |= ((raw_data[start+2] << 8) & 0xFF00);
		}
		return dest_port;
	}
	public byte[] getOptions()
	{
		if(this.options == null)
		{
			this.getHeaderLength();
			this.options = new byte[8];
			for(int i=0; i<8; i++)
			{
				options[i] = raw_data[start + this.headerLength - 8 + i];
			}
		}
		return this.options;
	}
	public byte[] getTCPData()
	{
		if(this.tcpData == null)
		{
			this.getHeaderLength();
			this.getDataLength();
			int data_start = this.start + this.headerLength;
			int data_end = this.start + this.dataLength;
			if(data_end > data_start)
			{
				int len = data_end - data_start;
				this.tcpData = new byte[len];
				try{
					System.arraycopy(raw_data, data_start, tcpData, 0, len);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
			else
			{
				this.tcpData = new byte[0];
			}
		}
		return tcpData;
	}
}
