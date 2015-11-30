package cn.seed.pcap.parser;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import cn.seed.pcap.parser.protocol.RTCP;
import cn.seed.pcap.parser.protocol.RTP;



public class PCAPPackageParser {
	//parse position
	private int current_p = 0;
	//the file position
	private int file_p = 0;
	
	private int type = -1;
	public PCAPFile pcapFile = new PCAPFile();
	
	//改用真实buffer，有多大就读多大
	//public int BUFFER_SIZE = 1024;
	//每次读取文件的buffer
	//public byte[] buffer = new byte[BUFFER_SIZE];
	private byte[] packageHeaderBuffer = new byte[24];
	//private byte[] headerBuffer = new byte[16];
	private ProtocolStackParser protocolStackParser = null;
	public String filename = null;
	private File file = null;
	private BufferedInputStream bufferedInputStream = null;
	private String srcIP = null;
	private String dstIP = null;
	private int srcPort = -1;
	private int dstPort = -1;
	
	public static void main(String[] args)
	{
		/*PCAPPackageParser parser = new PCAPPackageParser("d:\\319.pcap", 1);
		
		parser.checkPCAPHeader();
		parser.close();*/
	}
	
	public int getCurrentP(){
		return this.current_p;
	}
	
	public PCAPPackageParser(String filename, int type, String srcIP, String dstIP, int srcPort, int dstPort)
	{
		this.filename = filename;
		this.file = new File(filename);
		this.type = type;
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		try {
			this.bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
//		 int r = bufferedInputStream.read( bytes );
//		 if (r != len)
//		   throw new IOException("读取文件不正确");
		 

		 
	}
	public void close()
	{
		try {
			bufferedInputStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public Package getNextPackage()
	{
		if(current_p == 0)
			if(!checkPCAPHeader())
				return null;
		PackageHeader header = parseHeader();
		if(header == null)
			return null;
		PackageData data = parseData(header.getCapLen());
		if(data == null)
			return null;
		Package pack = new Package(header, data);
		protocolStackParser = new ProtocolStackParser(pack, 0, this.type, this.srcIP, this.dstIP, this.srcPort, this.dstPort);
		return pack;
	}
	
	public RTP getRTPData(){
		return this.protocolStackParser.getRTPData();
	}
	
	public RTCP getRTCPData(){
		return this.protocolStackParser.getRTCPData();
	}
	
	public byte[] getPureUDPData(){
		return this.protocolStackParser.getPureUDPData();
	}
	
	public int getPureUDPIPID(){
		return this.protocolStackParser.getPureUDPDataIPID();
	}
	
	//解析PackageData
	public PackageData parseData(long len)
	{
		int r = 0;
		int len_int = (int)len;
		//System.out.println("pcap package len = " + len);
		
		byte[] buf = new byte[len_int];
		try {
			r = bufferedInputStream.read(buf);
			if(r > 0)
				this.current_p += r;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		if(r != len_int)
			return null;
		PackageData data = new PackageData(buf, len_int);
		return data;
	}
	
	
	//解析Package header
	public PackageHeader parseHeader()
	{
		int r = 0;
		byte[] headerBuffer = new byte[16];
		try {
			r = bufferedInputStream.read(headerBuffer);
			if(r > 0)
				this.current_p += r;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		if(r != 16)
			return null;
		PackageHeader header = new PackageHeader();
		header.setRawHeader(headerBuffer);
		return header;
	}
	
	//暂时不做验证
	public boolean checkPCAPHeader() {
		// TODO Auto-generated method stub
		//跳过前6个字节
		int r = 0;
		try {
			r = bufferedInputStream.read(this.packageHeaderBuffer);
			if(r > 0)
				this.current_p += r;
//			for(int i=0; i<r; i++)
//			{
//				byte b1 = packageHeaderBuffer[i];
//				System.out.print(ByteUtil.byte2HexStr(b1) + " ");
//			}
//			byte b1 = packageHeaderBuffer[0];
//			byte b2 = packageHeaderBuffer[1];
//			byte b3 = packageHeaderBuffer[2];
//			byte b4 = packageHeaderBuffer[3];
//			System.out.println(ByteUtil.byte2HexStr(b1));
//			System.out.println(ByteUtil.byte2HexStr(b2));
//			System.out.println(ByteUtil.byte2HexStr(b3));
//			System.out.println(ByteUtil.byte2HexStr(b4));
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		if(r != 24)
			return false;
		
		return true;
	}
}
