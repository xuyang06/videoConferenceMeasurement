package cn.seed.pcap.parser.protocol;

import cn.seed.util.ByteUtil;




public class IP {
	public static final int TCP = 0;
	public static final int UDP = 1;
	public static final int UNKNOWN = 2;
	
	private byte[] identification = null;
	private int start = 0;
	private byte[] raw_data = null;
	private int fragmentOffset = -1;
	private int timeToLive = -1;
	private int headerLength = -1;
	private String version = null;
	private byte[] checksum = null;
	//private byte flags;
	private String srcAddr = null;
	private byte[] srcAddrBytes = null;
	private String destAddr = null;
	private byte[] destAddrBytes = null;
	private int totalLength = -1;
	private byte[] IPData = null;
	//TCP or UDP
	private int dataType = -1;
	public IP(byte[] raw_data, int start)
	{
		this.raw_data = raw_data;
		this.start = start;
	}
	
	public boolean isMoreFragment()
	{
		byte b = raw_data[start + 6];
		int r = b & 0x20;
		if(r == 0)
			return false;
		else
			return true;
	}
	
	public String getVersion()
	{
		if(this.version == null)
		{
			byte b = this.raw_data[start];
			int v = (int)(b & 0xF0);
			v = (v >> 4) & 0x0F;
			version = Integer.toString((int)v);
		}
		return this.version;
	}
	public int getHeaderLength()
	{
		if(headerLength == -1)
		{
			byte b = this.raw_data[start];
			
			this.headerLength = (int)(b & 0x0F);
			this.headerLength = this.headerLength * 4;
		}
		return this.headerLength;
	}
	
	
	
	public int getStart()
	{
		return start;
	}
	
	public int getTimeToLive()
	{
		if(timeToLive == -1)
		{
			byte b = this.raw_data[start + 8];
			timeToLive = (int)b;
		}
		return this.timeToLive;
	}
	
	public int getDataType()
	{
		if(dataType == -1)
		{
			byte b = this.raw_data[start + 9];
			int type = (int)b;
			if(type == 0x06)
				this.dataType = TCP;
			else if(type == 0x11)
				this.dataType = UDP;
			else
				this.dataType = UNKNOWN;
		}
		return dataType;
	}
	
	public String getSrcAddr()
	{
		if(this.srcAddr == null)
		{
			parseSrcAddr();
		}
		return this.srcAddr;
	}
	public byte[] getSrcAddrBytes()
	{
		if(this.srcAddrBytes == null)
		{
			parseSrcAddr();
		}
		return this.srcAddrBytes;
	}
	private void parseSrcAddr()
	{
		this.getHeaderLength();
		this.srcAddrBytes = new byte[4];
		try{
			System.arraycopy(this.raw_data, start+this.headerLength-8, this.srcAddrBytes, 0, 4);
		}catch(Exception e)
		{
			this.srcAddrBytes = null;
			return ;
		}
		StringBuffer str = new StringBuffer();
		str.append(Integer.toString(srcAddrBytes[0] & 0xFF));
		str.append(".");
		str.append(Integer.toString(srcAddrBytes[1] & 0xFF));
		str.append(".");
		str.append(Integer.toString(srcAddrBytes[2] & 0xFF));
		str.append(".");
		str.append(Integer.toString(srcAddrBytes[3] & 0xFF));
		this.srcAddr = str.toString();
	}
	
	private void parseDestAddr()
	{
		this.getHeaderLength();
		String version = this.getVersion();
		StringBuffer str = new StringBuffer();
		if(version.equals("4"))
		{
			this.destAddrBytes = new byte[4];
			try{
				System.arraycopy(this.raw_data, start+this.headerLength-4, this.destAddrBytes, 0, 4);
			}catch(Exception e)
			{
				this.srcAddrBytes = null;
				return ;
			}
			str.append(Integer.toString(destAddrBytes[0] & 0xFF));
			str.append(".");
			str.append(Integer.toString(destAddrBytes[1] & 0xFF));
			str.append(".");
			str.append(Integer.toString(destAddrBytes[2] & 0xFF));
			str.append(".");
			str.append(Integer.toString(destAddrBytes[3] & 0xFF));
		}else if(version.equals("6"))
		{
			this.destAddrBytes = new byte[16];
			try{
				System.arraycopy(this.raw_data, start+this.headerLength-16, this.destAddrBytes, 0, 4);
			}catch(Exception e)
			{
				this.srcAddrBytes = null;
				return ;
			}
			
			for(int i=0; i<16; i++)
			{
				str.append(Integer.toString(destAddrBytes[i] & 0xFF));
				if(i != 15)
					str.append(".");
			}
		}

		this.destAddr = str.toString();
	}
	

	private int oneByte2Int(byte b)
	{
		return b & 0xFF;
	}
	
	public byte[] getDestAddrBytes()
	{
		if(this.destAddrBytes == null)
		{
			parseDestAddr();
		}
		return this.destAddrBytes;
	}
	
	public String getDestAddr()
	{
		if(this.destAddr == null)
		{
			parseDestAddr();
		}
		return this.destAddr;
	}

	public int getTotalLength()
	{
		if(this.totalLength == -1)
		{
			byte[] buf = new byte[4];
			buf[0] = 0x00;
			buf[1] = 0x00;
			buf[2] = this.raw_data[start+2];
			buf[3] = this.raw_data[start+3];
			this.totalLength = ByteUtil.byte2Int_high(buf);
		}
		return totalLength;
	}
	public byte[] getIdentification()
	{
		if(this.identification == null)
		{
			identification = new byte[2];
			identification[0] = this.raw_data[start+5];
			identification[1] = this.raw_data[start+4];
		}
		return this.identification;
	}
	
	public int getIdentificationInteger(){
		if(this.identification == null)
		{
			identification = new byte[2];
			identification[0] = this.raw_data[start+5];
			identification[1] = this.raw_data[start+4];
		}
		int idInteger = ByteUtil.twoByte2Int(identification);
		return idInteger;
		
	}
	
	
	
	public byte getFlags()
	{
		byte b = this.raw_data[start+6];
		int v = (int)(b & 0xF0);
		v = (v >> 5) & 0x0F;
		return (byte)v;
	}
	public int getFlagOffset()
	{
		if(this.fragmentOffset == -1)
		{
			byte b1 = this.raw_data[start+6];
			byte b2 = this.raw_data[start+7];
			fragmentOffset = (int) b1 & 0x1f;
			fragmentOffset = fragmentOffset << 8;
			fragmentOffset += (int)b2 & 0x0f;
		}
		return this.fragmentOffset;
	}
	public byte[] getHeaderChecksum()
	{
		if(this.checksum == null)
		{
			checksum = new byte[2];
			checksum[0] = this.raw_data[start+10];
			checksum[1] = this.raw_data[start+11];
		}
		return checksum;
	}
	public byte[] getIPData()
	{
		if(this.IPData == null)
		{
			this.getHeaderLength();
			int data_start = this.start + this.headerLength;
			int data_end = this.start + this.totalLength;
			int len = data_end - data_start;
			if(len > 0)
			{
				this.IPData = new byte[len];
				try{
					System.arraycopy(raw_data, data_start, IPData, 0, len);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}else
			{
				IPData = new byte[0];
			}
		}
		return IPData;
	}
}
