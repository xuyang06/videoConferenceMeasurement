package cn.seed.pcap.parser;

public class PackageData {
	private byte[] raw_data = null;
	private int size = 0;
	private int start = 0;
	
	public PackageData(byte[] aRawData, int aSize){
		this.raw_data = aRawData;
		this.size = aSize;
		this.start = 0;
	}
	
	public byte[] getRawData(){
		return this.raw_data;
	}
	
	public int getSize(){
		return this.size;
	}
}
