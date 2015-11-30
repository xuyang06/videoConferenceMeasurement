import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import cn.seed.pcap.parser.*;
import cn.seed.util.ByteUtil;


public class TimeDiffParseFile {
	private String inFile = null;
	private int type = -1;
	private String filenameBefore = null;
	private String srcIPBefore = null;
	private String dstIPBefore = null;
	private int srcPortBefore = -1;
	private int dstPortBefore = -1; 
	private String CSRCNumBefore = null;
	private String filenameAfter = null;
	private String srcIPAfter = null;
	private String dstIPAfter = null;
	private int srcPortAfter = -1;
	private int dstPortAfter = -1;
	private String CSRCNumAfter = null;
	private String SSRCNumAfter = null;
	private PCAPComplexParser parser = null;
	private long adjustTime = 0;
	
	
	public TimeDiffParseFile(String inFile, int type, String filenameBefore, String srcIPBefore, String dstIPBefore, int srcPortBefore, 
			int dstPortBefore, String CSRCNumBefore, String filenameAfter, String srcIPAfter, String dstIPAfter, int srcPortAfter, int dstPortAfter, String CSRCNumAfter, String SSRCNumAfter, long adjustTime){
		this.type = type;
		this.inFile = inFile;
		this.filenameBefore = filenameBefore;
		this.srcIPBefore = srcIPBefore;
		this.dstIPBefore = dstIPBefore;
		this.srcPortBefore = srcPortBefore;
		this.dstPortBefore = dstPortBefore;
		this.CSRCNumBefore = CSRCNumBefore;
		this.filenameAfter = filenameAfter;
		this.srcIPAfter = srcIPAfter;
		this.dstIPAfter = dstIPAfter;
		this.srcPortAfter = srcPortAfter;
		this.dstPortAfter = dstPortAfter;
		this.CSRCNumAfter = CSRCNumAfter;
		this.SSRCNumAfter = SSRCNumAfter;
		this.adjustTime = adjustTime;
		this.parser = new PCAPComplexParser();
		this.parser.parseFileFromCSRC(this.type, this.filenameBefore, this.srcIPBefore, this.dstIPBefore, this.srcPortBefore, this.dstPortBefore, this.CSRCNumBefore,
				this.filenameAfter, this.srcIPAfter, this.dstIPAfter, this.srcPortAfter, this.dstPortAfter, this.CSRCNumAfter, this.SSRCNumAfter, this.adjustTime);
		this.parser.printDiffLenFile(this.inFile);
		
	}
	

	

	public static void main(String[] args)
	{
		//String inFilePath = "D:\\Research\\video_conference\\googleplusNew\\test\\download_lost002_feng.pcap";
		//String outFilePath = "D:\\Research\\video_conference\\googleplusNew\\test\\download_lost002_fengVideoOutput.txt";
		//String inFilePath = "D:\\Research\\video_conference\\google\\google+_11_28\\download_20_chenguang.pcap";
		String inFile = "D:\\delayVideo\\delayVideo.txt";
		long adjustTime = -6180000;
		int type = ProtocolStackParser.RTPType;
		String filenameBefore = "D:\\delayVideo\\google_normal_sender.pcap";
		String srcIPBefore = "192.168.1.3";
		String dstIPBefore = "173.194.76.127";
		int srcPortBefore = 51218;
		int dstPortBefore = 19305; 
		String CSRCNumBefore = "50388670";
		String filenameAfter = "D:\\delayVideo\\google_normal-receiver.pcap";
		String srcIPAfter = "173.194.76.127";
		String dstIPAfter = "192.168.1.4";
		int srcPortAfter = 19305;
		int dstPortAfter = 62156;
		String CSRCNumAfter = "50388670";
		String SSRCNumAfter = "33554432";
		
		/*String filenameBefore = "D:\\Research\\video_conference\\ichat\\1_3\\lc012_1view_download002.pcap";
		String srcIPBefore = "192.168.1.21";
		String dstIPBefore = "128.238.35.187";
		int srcPortBefore = 16402;
		int dstPortBefore = 62498; 
		String SSRCNumBefore = "886815753";
		//String SSRCNumBefore = "2769331122"; 
		String filenameAfter = "D:\\Research\\video_conference\\ichat\\1_3\\feng_1view_download002.pcap";
		String srcIPAfter = "128.238.35.133";
		String dstIPAfter = "192.168.137.117";
		int srcPortAfter = 58966;
		int dstPortAfter = 16402;
		String SSRCNumAfter = "886815753";*/
		//String SSRCNumAfter = "2769331122"; 
		
		TimeDiffParseFile timeParse = new TimeDiffParseFile(inFile, type, filenameBefore, srcIPBefore, dstIPBefore, srcPortBefore, dstPortBefore, CSRCNumBefore,
				filenameAfter, srcIPAfter, dstIPAfter, srcPortAfter, dstPortAfter, CSRCNumAfter, SSRCNumAfter, adjustTime);
		
	}
}
