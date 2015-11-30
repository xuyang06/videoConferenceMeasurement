package cn.seed.pcap.parser.protocol;


//pcap的文件格式
public class Ethernet2 {
	public static final int UNKNOWN = 0x0000;
	public static final int IPv4 = 0x0800;
	public static final int IPv6 = 0x86DD;
	public static final int NONE = -1;
	private byte mac_raw_data[] = null;
	private byte raw_data[] = null;
	private int start;
	
	private byte[] preamble = null;
	private byte[] macSource = null;
	private byte[] macDest = null;
	private byte[] macData = null;
	private int macDataLen = -1;
	private int macDataType = -1;
	public Ethernet2(byte []raw_data, int start)
	{
		this.raw_data = raw_data;
		this.start = start;
	}
	
	public byte[] getMacSrcAddr()
	{
		if(this.macSource == null)
		{
			this.macSource = new byte[6];
			try{
				System.arraycopy(raw_data, start+6, macSource, 0, 6);
			}catch(Exception e)
			{
				e.printStackTrace();
				return null;
			}
		}
		return this.macSource;
	}
	
	public byte[] getMacDestAddr()
	{
		if(this.macDest == null)
		{
			this.macDest = new byte[6];
			try{
				System.arraycopy(raw_data, start, macDest, 0, 6);
			}catch(Exception e)
			{
				e.printStackTrace();
				return null;
			}
		}
		return this.macDest;
	}
	
	public int getDataStart()
	{
		return start + 14;
	}
	
	public int getMacDataType()
	{
		if(this.macDataType == -1)
		{
			int b1 = (int)this.raw_data[12];
			int b2 = (int)this.raw_data[13];
			if(b1 == 0x08 && b2 == 0x00)
				this.macDataType = IPv4;
			else if(b1 == 0x86 && b2 == 0xDD)
				this.macDataType = IPv6;
			else
				this.macDataType = Ethernet2.UNKNOWN;
		}
		return this.macDataType;
	}
	
}
