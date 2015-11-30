package cn.seed.pcap.parser.protocol;

import java.util.Arrays;


//pcap报文格式
//0-1:source_port
//2-3:dest_port
//4-5:length (包括头和数据)
//6-7:checksum

//头一共有8个字节
public class UDP {
	private int source_port = -1;
	private int dest_port = -1;
	private int length = -1;
	private int dataLength = -1;
	private int dataStart = -1;
	
	private int start;
	private byte[] raw_data;
	private byte[] checksum = null;
	private byte[] udpData = null;
//	private int getStart()
//	{
//		return this.start;
//	}
	public UDP(byte[] raw_data, int start)
	{
		this.raw_data = raw_data;
		this.start = start;
	}
	
	//UDP的长度-8 （8是头长度）
	public int getDataLength()
	{
		if(this.dataLength == -1)
		{
			this.getLength();
			this.dataLength = this.length - 8;
			if(this.dataLength < 0)
				this.dataLength = 0;
		}
		return this.dataLength;
	}
	
	//UDP头固定8位长
	public int getDataStart()
	{
		if(dataStart == -1)
		{
			getLength();
			dataStart = start + 8;
		}
		return dataStart;
	}
	public int getSourcePort()
	{
		if(this.source_port == -1)
		{
			source_port = raw_data[start+1] & 0xFF;
			source_port |= ((raw_data[start] << 8) & 0xFF00);
		}
		
		return this.source_port;
	}
	
	public int getDestPort()
	{
		if(this.dest_port == -1)
		{
			dest_port = raw_data[start+3] & 0xFF;
			dest_port |= ((raw_data[start+2] << 8) & 0xFF00);
		}
		return this.dest_port;
	}
	
	
	//2位
	public int getLength()
	{
		if(this.length == -1)
		{
			byte low = raw_data[start+5];
			byte high = raw_data[start+4];
			length = (int)low & 0xFF;
			length |= ((int)high << 8) & 0xFF00;
			
		}
		return this.length;
	}
	
	public byte[] getChecksum()
	{
		if(this.checksum == null)
		{
			this.checksum = new byte[2];
			checksum[0] = raw_data[start+6];
			checksum[1] = raw_data[start+7];
		}
		return this.checksum;
	}
	
	public byte[] getUDPData()
	{
		if(this.udpData == null)
		{
			int len = getDataLength();
			if(len < 0)
			{
				return null;
			}	
			udpData = new byte[len];
			getDataStart();
			int aa_len = raw_data.length;
			
			//wireShard抓取的包有问题
			if(len > aa_len - this.start)
			{
				this.udpData = new byte[0];
				return udpData;
			}
			//System.out.println(len + "\n");
			if(len != 0 )
			{
				try{
					System.arraycopy(raw_data, this.dataStart, udpData, 0, len);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
				
		}
		return this.udpData;
	}
}
