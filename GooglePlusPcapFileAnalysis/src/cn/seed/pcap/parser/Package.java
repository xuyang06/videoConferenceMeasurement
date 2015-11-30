package cn.seed.pcap.parser;


import cn.seed.util.ByteUtil;


public class Package {
	private PackageHeader header = null;
	private PackageData data = null;
	
	public Package (PackageHeader aHeader, PackageData aData){
		this.header = aHeader;
		this.data = aData;
	}
	
	public PackageHeader getHeader(){
		return this.header;	
	}
	
	public PackageData getData(){
		return this.data;
	}
	
	public String printBody()
	{
		if(data == null || data.getRawData() == null)
			return "";
		StringBuffer buf = new StringBuffer();
		for(int i=0 ; i<data.getRawData().length; i++)
		{
			byte b = data.getRawData()[i];
			String bb = ByteUtil.byte2HexStr(b);
			System.out.print(bb + " ");
			buf.append(bb);
			buf.append(" ");
		}
		System.out.println("");
		return buf.toString();
	}
}
