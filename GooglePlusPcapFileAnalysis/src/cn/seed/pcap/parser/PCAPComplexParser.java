package cn.seed.pcap.parser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import cn.seed.pcap.parser.protocol.RTCP;
import cn.seed.pcap.parser.protocol.RTP;
import cn.seed.pcap.parser.usefulStructure.RTCPStructure;
import cn.seed.pcap.parser.usefulStructure.RTPStructure;
import cn.seed.pcap.parser.complexParserStructure.*;

public class PCAPComplexParser {
	private int type;
	private int lastTime = 10*60*1000000;
	private List<UniqueFrame> uniqueFrameListsBefore = new ArrayList<UniqueFrame>();
	private List<UniqueFrame> uniqueFrameListsAfter = new ArrayList<UniqueFrame>();
	private int FPSTotalBefore = 0;
	private int FPSTotalAfter = 0;
	/*private int nonrtpPacketNum = 0;
	private int rtpNonSSRCNum = 0;
	private int rtpSSRCNum = 0;
	private long nonrtpPacketLen = 0;
	private long rtpNonSSRCLen = 0;
	private long rtpSSRCLen = 0;*/
	private List<Long> nonrtpPacketLenList = new ArrayList<Long> ();
	private List<Long> rtpNonSSRCLenList = new ArrayList<Long> ();
	private List<Long> rtpSSRCLenList = new ArrayList<Long> ();
	private List<Long> timeDiffList = new ArrayList<Long> ();
	
	private long retransPacketLen = 0;
	private long nonRetransPacketLen = 0;
	private List<Integer> lostPacketIndics = new ArrayList<Integer>();
	private long lostPacketLenTotal = 0;
	private List<Integer> retransPacketIndics = new ArrayList<Integer>();
	private int totalPacketNumber = -1;
	private int totalLossPacketNumber = -1;
	private int largestRetransmissionNum = 0;
	private int largestNoLossRetransRecovRetransmissionNum = 0;
	private int largestNoLossRetransNoRecovRetransmissionNum = 0;
	private int largestLossRetransRetransmissionNum = 0;
	private List<List<Long>> retransmissionMatrix = new ArrayList<List<Long>> ();
	private List<List<Long>> noLossRetransRecovRetransmissionMatrix = new ArrayList<List<Long>> ();
	private List<List<Long>> noLossRetransNoRecovRetransmissionMatrix = new ArrayList<List<Long>> ();
	private List<List<Long>> lossRetransRetransmissionMatrix = new ArrayList<List<Long>> ();
	
	public void parseFile(int type, String filenameBefore, String srcIPBefore, String dstIPBefore, int srcPortBefore, int dstPortBefore, String SSRCNumBefore,
			String filenameAfter, String srcIPAfter, String dstIPAfter, int srcPortAfter, int dstPortAfter, String SSRCNumAfter)
	{
		this.type = type;
		int findFirstMatch = 0;
		int sequenceItem = 65536;
		int securityRegion = 100;
		int enterSecurityRegionBefore = 0;
		int enterSecurityRegionAfter = 0;
		int sequenceItemBefore = 0;
		int sequenceItemAfter = 0;
		int BackoffNumberBefore = securityRegion;
		int BackoffNumberAfter = securityRegion;
		int endBefore = 0;
		int endAfter = 0;
		int nextPackBefore = 1;
		int nextPackBeforeIndentify = 1;
		long captureTimeBeforeLast = -1;
		long captureTimeAfterLast = -1;
		PCAPPackageParser parserBefore = new PCAPPackageParser(filenameBefore, this.type, srcIPBefore, dstIPBefore, srcPortBefore, dstPortBefore);
		PCAPPackageParser parserAfter = new PCAPPackageParser(filenameAfter, this.type, srcIPAfter, dstIPAfter, srcPortAfter, dstPortAfter);		
		Package packBefore = parserBefore.getNextPackage();
		Package packAfter = parserAfter.getNextPackage();
		int rtpBeforeSequenceNumberLast = -1;
		int rtpAfterSequenceNumberLast = -1;
		
		
		while( (packBefore != null) && (packAfter != null))
		{	
			//System.out.println("here");
			if ( this.type == ProtocolStackParser.RTPType ){
				//System.out.println("i am here");
				RTP rtpBefore = parserBefore.getRTPData();
				RTP rtpAfter = parserAfter.getRTPData();				
				if ( ( rtpBefore != null ) && ( ( rtpAfter != null ) ) ){
					//System.out.println("here again");
					long captureTimeBefore = packBefore.getHeader().getTime();
					long captureTimeAfter = packAfter.getHeader().getTime();
					long oriLengthBefore = packBefore.getHeader().getOriLen();
					long oriLengthAfter = packAfter.getHeader().getOriLen();
					int rtpBeforeVersion = rtpBefore.getVersion();
					int rtpAfterVersion = rtpAfter.getVersion();
					long rtpBeforeGenerateTime = rtpBefore.getTimestamp();
					long rtpAfterGenerateTime = rtpAfter.getTimestamp();
					int rtpBeforeSequenceNumber = rtpBefore.getSequenceNumber();
					int rtpAfterSequenceNumber = rtpAfter.getSequenceNumber();
					long rtpBeforeSSRC = rtpBefore.getSSRC();
					long rtpAfterSSRC = rtpAfter.getSSRC();
					
					if ( rtpBeforeVersion != 2 ){
						if ( (findFirstMatch == 1) && (endBefore == 0) ){
							if (nextPackBefore == 1){
								/*this.nonrtpPacketNum += 1;
								this.nonrtpPacketLen += oriLengthBefore;*/
								this.nonrtpPacketLenList.add(oriLengthBefore);
							}
						}
						nextPackBefore = 1;
						packBefore = parserBefore.getNextPackage();
						continue;
					}
					
					if ( (findFirstMatch == 1) && (endBefore == 0) ){
						if (nextPackBefore == 1){
							if (SSRCNumBefore != null){
								if ( !String.valueOf(rtpBeforeSSRC).equalsIgnoreCase(SSRCNumBefore)){
									/*this.rtpNonSSRCNum += 1;
									this.rtpNonSSRCLen += oriLengthBefore;*/
									this.rtpNonSSRCLenList.add(oriLengthBefore);
									nextPackBefore = 1;
									packBefore = parserBefore.getNextPackage();
									continue;	
								}else{
									/*this.rtpSSRCNum += 1;
									this.rtpSSRCLen += oriLengthBefore;*/
									this.rtpSSRCLenList.add(oriLengthBefore);
								}
							}else{
								this.rtpSSRCLenList.add(oriLengthBefore);
							}
						}
					}
					
					if ( rtpAfterVersion != 2){
						nextPackBefore = 0;
						packAfter = parserAfter.getNextPackage();
						continue;
					}
					if (SSRCNumBefore != null){
						if ( !String.valueOf(rtpBeforeSSRC).equalsIgnoreCase(SSRCNumBefore)){
							nextPackBefore = 1;
							packBefore = parserBefore.getNextPackage();
							continue;	
						}
					}
					if (SSRCNumAfter != null){
						if ( !String.valueOf(rtpAfterSSRC).equalsIgnoreCase(SSRCNumAfter)){
							nextPackBefore = 0;
							packAfter = parserAfter.getNextPackage();
							continue;	
						}
					}
					//System.out.println("here again");
					if (findFirstMatch == 0){
						if ( rtpBeforeGenerateTime < rtpAfterGenerateTime){
							nextPackBefore = 1;
							packBefore = parserBefore.getNextPackage();
							continue;
						}
						if ( rtpBeforeGenerateTime > rtpAfterGenerateTime){
							nextPackBefore = 0;
							packAfter = parserAfter.getNextPackage();
							continue;
						}
						if ( rtpBeforeSequenceNumber < rtpAfterSequenceNumber){
							nextPackBefore = 1;
							packBefore = parserBefore.getNextPackage();
							continue;	
						}
						if ( rtpBeforeSequenceNumber > rtpAfterSequenceNumber){
							nextPackBefore = 0;
							packAfter = parserAfter.getNextPackage();
							continue;
						}
						if ( rtpBeforeSequenceNumber == rtpAfterSequenceNumber){
							/*this.rtpSSRCNum += 1;
							this.rtpSSRCLen += oriLengthBefore;*/
							this.rtpSSRCLenList.add(oriLengthBefore);
							captureTimeBeforeLast = captureTimeBefore + this.lastTime;
							captureTimeAfterLast = captureTimeAfter + this.lastTime;
							rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
							rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
							UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
							UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
							nextPackBefore = 1;
							packBefore = parserBefore.getNextPackage();
							packAfter = parserAfter.getNextPackage();
							findFirstMatch = 1;
							continue;
						} 					
					}else{
						nextPackBeforeIndentify = 0;
						if (captureTimeBefore < captureTimeBeforeLast){
							if ( ( rtpBeforeSequenceNumberLast > ( sequenceItem - securityRegion) ) && ( rtpBeforeSequenceNumber < securityRegion) && enterSecurityRegionBefore == 0){
								enterSecurityRegionBefore = 1;
								BackoffNumberBefore -= 1;
								rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
								sequenceItemBefore += 1;
								UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + sequenceItemBefore*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
								nextPackBefore = 1;
								nextPackBeforeIndentify = 1;
								packBefore = parserBefore.getNextPackage();
							}else if ( ( enterSecurityRegionBefore == 1) && (BackoffNumberBefore != 0)){
								if (  rtpBeforeSequenceNumber > ( sequenceItem - securityRegion) ){
									BackoffNumberBefore -= 1;
									rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + ( sequenceItemBefore - 1)*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
									nextPackBefore = 1;
									nextPackBeforeIndentify = 1;
									packBefore = parserBefore.getNextPackage();
								}else{
									BackoffNumberBefore -= 1;
									rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + sequenceItemBefore*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
									nextPackBefore = 1;
									nextPackBeforeIndentify = 1;
									packBefore = parserBefore.getNextPackage();
								}
							}else if ( ( enterSecurityRegionBefore == 1) && (BackoffNumberBefore == 0) ){
								if (  rtpBeforeSequenceNumber > ( sequenceItem - securityRegion ) ){
									BackoffNumberBefore = securityRegion;
									rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + ( sequenceItemBefore - 1)*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
									nextPackBefore = 1;
									nextPackBeforeIndentify = 1;
									packBefore = parserBefore.getNextPackage();
									enterSecurityRegionBefore = 0;
								}else{
									BackoffNumberBefore = securityRegion;
									rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + sequenceItemBefore*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
									nextPackBefore = 1;
									nextPackBeforeIndentify = 1;
									packBefore = parserBefore.getNextPackage();
									enterSecurityRegionBefore = 0;
								}
							}else{
								rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
								UniqueFrame.addUniqueFrameToList(rtpBeforeGenerateTime, rtpBeforeSequenceNumber + sequenceItemBefore*sequenceItem, captureTimeBefore, oriLengthBefore, this.uniqueFrameListsBefore);
								nextPackBefore = 1;
								nextPackBeforeIndentify = 1;
								packBefore = parserBefore.getNextPackage();
							}		
						}else{
							endBefore = 1;
						}
						
						if (captureTimeAfter < captureTimeAfterLast){
							if ( ( rtpAfterSequenceNumberLast > ( sequenceItem - securityRegion) ) && ( rtpAfterSequenceNumber < securityRegion) && enterSecurityRegionAfter == 0){
								enterSecurityRegionAfter = 1;
								BackoffNumberAfter -= 1;
								rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
								sequenceItemAfter += 1;
								UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + sequenceItemAfter*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
								if (nextPackBeforeIndentify == 0){
									nextPackBefore = 0; 
								}
								packAfter = parserAfter.getNextPackage();
							}else if ( ( enterSecurityRegionAfter == 1) && (BackoffNumberAfter != 0)){
								if (  rtpAfterSequenceNumber > (sequenceItem - securityRegion) ){
									BackoffNumberAfter -= 1;
									rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + ( sequenceItemAfter - 1)*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
									if (nextPackBeforeIndentify == 0){
										nextPackBefore = 0; 
									}
									packAfter = parserAfter.getNextPackage();
								}else{
									BackoffNumberAfter -= 1;
									rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + sequenceItemAfter*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
									if (nextPackBeforeIndentify == 0){
										nextPackBefore = 0; 
									}
									packAfter = parserAfter.getNextPackage();
								}
							}else if ( ( enterSecurityRegionAfter == 1) && (BackoffNumberAfter == 0) ){
								if (  rtpAfterSequenceNumber > ( sequenceItem - securityRegion ) ){
									BackoffNumberAfter = securityRegion;
									rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + ( sequenceItemAfter - 1)*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
									if (nextPackBeforeIndentify == 0){
										nextPackBefore = 0; 
									}
									packAfter = parserAfter.getNextPackage();
									enterSecurityRegionAfter = 0;
								}else{
									BackoffNumberAfter = securityRegion;
									rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
									UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + sequenceItemAfter*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
									if (nextPackBeforeIndentify == 0){
										nextPackBefore = 0; 
									}
									packAfter = parserAfter.getNextPackage();
									enterSecurityRegionAfter = 0;
								}
							}else{
								rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
								UniqueFrame.addUniqueFrameToList(rtpAfterGenerateTime, rtpAfterSequenceNumber + sequenceItemAfter*sequenceItem, captureTimeAfter, oriLengthAfter, this.uniqueFrameListsAfter);
								if (nextPackBeforeIndentify == 0){
									nextPackBefore = 0; 
								}
								packAfter = parserAfter.getNextPackage();
							}		
						}else{
							endAfter = 1;
						}
						
						if ( ( endBefore == 1) && ( endAfter == 1) ){
							break;
						}
						
					}
					continue;
					
				}else{
					if ( rtpBefore == null ){
						packBefore = parserBefore.getNextPackage(); 
					} 
					if ( rtpAfter == null ) {
						packAfter = parserAfter.getNextPackage();
					}
					continue;
				}
			}else{
				break;
			}
		}
		//System.out.print("End First Round\n");
		parserBefore.close();
		parserAfter.close();
	}
	
	
	public void parseFileFromCSRC(int type, String filenameBefore, String srcIPBefore, String dstIPBefore, int srcPortBefore, int dstPortBefore, String CSRCNumBefore,
			String filenameAfter, String srcIPAfter, String dstIPAfter, int srcPortAfter, int dstPortAfter, String CSRCNumAfter, String SSRCNumAfter, long adjustTime)
	{
		this.type = type;
		int findFirstMatch = 0;
		int sequenceItem = 65536;
		long rtpBeforeGenerateTimeLastTime = -1;
		long rtpAfterGenerateTimeLastTime = -1;
		long captureTimeBeforeLast = -1;
		long captureTimeAfterLast = -1;
		PCAPPackageParser parserBefore = new PCAPPackageParser(filenameBefore, this.type, srcIPBefore, dstIPBefore, srcPortBefore, dstPortBefore);
		PCAPPackageParser parserAfter = new PCAPPackageParser(filenameAfter, this.type, srcIPAfter, dstIPAfter, srcPortAfter, dstPortAfter);		
		Package packBefore = parserBefore.getNextPackage();
		Package packAfter = parserAfter.getNextPackage();
		int rtpBeforeSequenceNumberLast = -1;
		int rtpAfterSequenceNumberLast = -1;
		int end = 0;
		
		while( (packBefore != null) && (packAfter != null))
		{	
			//System.out.println("here");
			if ( this.type == ProtocolStackParser.RTPType ){
				//System.out.println("i am here");
				RTP rtpBefore = parserBefore.getRTPData();
				RTP rtpAfter = parserAfter.getRTPData();				
				if ( ( rtpBefore != null ) && ( ( rtpAfter != null ) ) ){
					//System.out.println("here again");
					long captureTimeBefore = packBefore.getHeader().getTime();
					long captureTimeAfter = packAfter.getHeader().getTime();
					long oriLengthBefore = packBefore.getHeader().getOriLen();
					long oriLengthAfter = packAfter.getHeader().getOriLen();
					int rtpBeforeVersion = rtpBefore.getVersion();
					int rtpAfterVersion = rtpAfter.getVersion();
					long rtpBeforeGenerateTime = rtpBefore.getTimestamp();
					long rtpAfterGenerateTime = rtpAfter.getTimestamp();
					int rtpBeforeSequenceNumber = rtpBefore.getSequenceNumber();
					int rtpAfterSequenceNumber = rtpAfter.getSequenceNumber();
					long rtpBeforeCSRC = rtpBefore.getCSRC();
					long rtpAfterCSRC = rtpAfter.getCSRC();
					long rtpAfterSSRC = rtpAfter.getSSRC();
					
					if ( rtpBeforeVersion != 2 ){
						packBefore = parserBefore.getNextPackage();
						continue;
					}
					
					if (CSRCNumBefore != null){
						if ( !String.valueOf(rtpBeforeCSRC).equalsIgnoreCase(CSRCNumBefore)){	
							packBefore = parserBefore.getNextPackage();
							continue;	
						}else{
									/*this.rtpSSRCNum += 1;
									this.rtpSSRCLen += oriLengthBefore;*/
						}
					}else{
						packBefore = parserBefore.getNextPackage();
						continue;
					}
						
					
					if ( rtpAfterVersion != 2){
						packAfter = parserAfter.getNextPackage();
						continue;
					}
					if (CSRCNumBefore != null){
						if ( !String.valueOf(rtpBeforeCSRC).equalsIgnoreCase(CSRCNumBefore)){
							packBefore = parserBefore.getNextPackage();
							continue;	
						}
					}
					if (CSRCNumAfter != null){
						if ( !String.valueOf(rtpAfterCSRC).equalsIgnoreCase(CSRCNumAfter)){
							packAfter = parserAfter.getNextPackage();
							continue;	
						}
					}
					if (SSRCNumAfter != null){
						if ( !String.valueOf(rtpAfterSSRC).equalsIgnoreCase(SSRCNumAfter)){
							packAfter = parserAfter.getNextPackage();
							continue;	
						}
					}
					
					//System.out.println("here again");
					if (findFirstMatch == 0){
						if ( rtpBeforeGenerateTime < rtpAfterGenerateTime){
							packBefore = parserBefore.getNextPackage();
							continue;
						}
						if ( rtpBeforeGenerateTime > rtpAfterGenerateTime){
							packAfter = parserAfter.getNextPackage();
							continue;
						}
						if ( rtpBeforeGenerateTime == rtpAfterGenerateTime){
							/*this.rtpSSRCNum += 1;
							this.rtpSSRCLen += oriLengthBefore;*/
							this.rtpSSRCLenList.add(oriLengthBefore);
							rtpBeforeGenerateTimeLastTime = rtpBeforeGenerateTime;
							rtpAfterGenerateTimeLastTime = rtpAfterGenerateTime;
							captureTimeBeforeLast = captureTimeBefore + this.lastTime;
							captureTimeAfterLast = captureTimeAfter + this.lastTime;
							rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
							rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
							//long timeDiff = captureTimeAfter - captureTimeBefore - adjustTime;
							if (oriLengthBefore == oriLengthAfter){
								long timeDiff = captureTimeAfter - captureTimeBefore - adjustTime;
								System.out.println(captureTimeAfter);
								System.out.println(captureTimeBefore);
								System.out.println(adjustTime);
								System.out.println(timeDiff);
								timeDiffList.add(timeDiff);
							}
							packBefore = parserBefore.getNextPackage();
							packAfter = parserAfter.getNextPackage();
							findFirstMatch = 1;
							continue;
						} 					
					}else{
						if ( rtpBeforeGenerateTime == rtpBeforeGenerateTimeLastTime) {
							packBefore = parserBefore.getNextPackage();
							continue;
						}
						if ( rtpAfterGenerateTime == rtpAfterGenerateTimeLastTime) {
							packAfter = parserAfter.getNextPackage();
							continue;
						}
						
						if ( ( captureTimeBefore < captureTimeBeforeLast ) && ( captureTimeAfter < captureTimeAfterLast ) ){
							if (rtpBeforeGenerateTime < rtpAfterGenerateTime){
								packBefore = parserBefore.getNextPackage();
								continue;
							}
							if ( rtpBeforeGenerateTime > rtpAfterGenerateTime){
								packAfter = parserAfter.getNextPackage();
								continue;
							}
							if ( rtpBeforeGenerateTime == rtpAfterGenerateTime){
								/*this.rtpSSRCNum += 1;
								this.rtpSSRCLen += oriLengthBefore;*/
								this.rtpSSRCLenList.add(oriLengthBefore);
								rtpBeforeGenerateTimeLastTime = rtpBeforeGenerateTime;
								rtpAfterGenerateTimeLastTime = rtpAfterGenerateTime;
								captureTimeBeforeLast = captureTimeBefore + this.lastTime;
								captureTimeAfterLast = captureTimeAfter + this.lastTime;
								rtpBeforeSequenceNumberLast = rtpBeforeSequenceNumber;
								rtpAfterSequenceNumberLast = rtpAfterSequenceNumber;
								if (oriLengthBefore == oriLengthAfter){
									long timeDiff = captureTimeAfter - captureTimeBefore - adjustTime;
									timeDiffList.add(timeDiff);
								}
								packBefore = parserBefore.getNextPackage();
								packAfter = parserAfter.getNextPackage();
								findFirstMatch = 1;
								continue;
							} 	
						}else{
							end = 1;
							break;
						}
					}
					continue;
					
				}else{
					if ( rtpBefore == null ){
						packBefore = parserBefore.getNextPackage(); 
					} 
					if ( rtpAfter == null ) {
						packAfter = parserAfter.getNextPackage();
					}
					continue;
				}
			}else{
				break;
			}
		}
		//System.out.print("End First Round\n");
		parserBefore.close();
		parserAfter.close();
	}
	
	public void printDiffLenFile(String inFilePath){
		File write = new File(inFilePath);
		try{
			BufferedWriter bw = new BufferedWriter(new FileWriter(write));
			for (int i = 0; i < timeDiffList.size(); i ++ ){
				bw.write(timeDiffList.get(i) + " " +"\015\012");
			}
			bw.close();
		}catch(FileNotFoundException e){ 
			System.out.println (e);
		}
		catch(IOException e){
			System.out.println (e);
		}
		
		
	}
	
	private void printListInfo(String listPath, List<UniqueFrame> uniqueFrameLists){
		File write = new File(listPath);
		try{
			BufferedWriter bw = new BufferedWriter(new FileWriter(write));
			for (int i = 0; i < uniqueFrameLists.size(); i ++ ){
				for (int j = 0; j < uniqueFrameLists.get(i).getPacketsList().size(); j ++){
					for (int k = 0; k < uniqueFrameLists.get(i).getPacketsList().get(j).getCaptureTimeList().size(); k++){
						bw.write(uniqueFrameLists.get(i).getGenerateTime() + " " + uniqueFrameLists.get(i).getPacketsList().get(j).getSequenceNumber() + " "+ uniqueFrameLists.get(i).getPacketsList().get(j).getCaptureTimeList().get(k) +"\015\012");
					}
				}
			}
			bw.close();
		}catch(FileNotFoundException e){ 
			System.out.println (e);
		}
		catch(IOException e){
			System.out.println (e);
		}
	}
	
	public int getFPSTotalBefore(){
		return this.FPSTotalBefore;
	}
	
	public int getFPSTotalAfter(){
		return this.FPSTotalAfter;
	}
	
	public void caculateLossInfo(){
		Collections.sort(this.uniqueFrameListsBefore);
		Collections.sort(this.uniqueFrameListsAfter);
		this.FPSTotalBefore = this.uniqueFrameListsBefore.size();
		this.FPSTotalAfter = this.uniqueFrameListsAfter.size();
		String listPathBefore = "D:\\Research\\video_conference\\google\\resultnew\\FramelistBefore.txt";
		String listPathAfter = "D:\\Research\\video_conference\\google\\resultnew\\FramelistAfter.txt";
		printListInfo(listPathBefore, this.uniqueFrameListsBefore);
		printListInfo(listPathAfter, this.uniqueFrameListsAfter);
		int first = 1;
		int beforeIndex = 0;
		int afterIndex = 0;
		while (  ( beforeIndex < this.uniqueFrameListsBefore.size() ) && ( afterIndex < this.uniqueFrameListsAfter.size()) ){
			if ( first == 1){
				if ( this.uniqueFrameListsBefore.get(beforeIndex).compare(this.uniqueFrameListsAfter.get(afterIndex)) < 0){
					beforeIndex = beforeIndex + 1;
				}else if ( this.uniqueFrameListsBefore.get(beforeIndex).compare(this.uniqueFrameListsAfter.get(afterIndex)) > 0){
					afterIndex = afterIndex + 1;
				}else{
					first = 0;
					this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketInfo(this.uniqueFrameListsAfter.get(afterIndex));
					this.lostPacketIndics = this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketIndics();
					this.lostPacketLenTotal += this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketLenTotal();
					this.retransPacketIndics = this.uniqueFrameListsBefore.get(beforeIndex).getRetransPacketIndics();
					this.totalPacketNumber = this.uniqueFrameListsBefore.get(beforeIndex).getTotalPacketNumber();
					this.totalLossPacketNumber = this.uniqueFrameListsBefore.get(beforeIndex).getTotalLossPacketNumber();
					this.largestRetransmissionNum = this.uniqueFrameListsBefore.get(beforeIndex).getLargestRetransmissionNum();
					this.largestNoLossRetransRecovRetransmissionNum = this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransRecovRetransmissionNum();
					this.largestNoLossRetransNoRecovRetransmissionNum = this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransNoRecovRetransmissionNum();
					this.largestLossRetransRetransmissionNum = this.uniqueFrameListsBefore.get(beforeIndex).getLargestLossRetransRetransmissionNum();
					this.retransmissionMatrix = this.uniqueFrameListsBefore.get(beforeIndex).getRetransmissionMatrix();
					this.noLossRetransRecovRetransmissionMatrix = this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransRecovRetransmissionMatrix();
					this.noLossRetransNoRecovRetransmissionMatrix = this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransNoRecovRetransmissionMatrix();
					this.lossRetransRetransmissionMatrix = this.uniqueFrameListsBefore.get(beforeIndex).getLossRetransRetransmissionMatrix();
					beforeIndex = beforeIndex + 1;
					afterIndex = afterIndex + 1;
				}
			}else{
				if ( this.uniqueFrameListsBefore.get(beforeIndex).compare(this.uniqueFrameListsAfter.get(afterIndex)) < 0){
					this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketInfo(null);
					this.lostPacketIndics.addAll(this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketIndics());
					this.lostPacketLenTotal += this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketLenTotal();
					this.retransPacketIndics.addAll(this.uniqueFrameListsBefore.get(beforeIndex).getRetransPacketIndics());
					this.totalPacketNumber += this.uniqueFrameListsBefore.get(beforeIndex).getTotalPacketNumber();
					this.totalLossPacketNumber += this.uniqueFrameListsBefore.get(beforeIndex).getTotalLossPacketNumber();
					this.largestRetransmissionNum = Math.max(this.largestRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestRetransmissionNum());
					this.largestNoLossRetransRecovRetransmissionNum = Math.max(this.largestNoLossRetransRecovRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransRecovRetransmissionNum());
					this.largestNoLossRetransNoRecovRetransmissionNum = Math.max(this.largestNoLossRetransNoRecovRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransNoRecovRetransmissionNum());
					this.largestLossRetransRetransmissionNum = Math.max(this.largestLossRetransRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestLossRetransRetransmissionNum());
					mergeRetransMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getRetransmissionMatrix());
					mergeNoLossRetransRecovMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransRecovRetransmissionMatrix());
					mergeNoLossRetransNoRecovMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransNoRecovRetransmissionMatrix());
					mergelossRetransMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getLossRetransRetransmissionMatrix());
					beforeIndex = beforeIndex + 1;
				}else{
					this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketInfo(this.uniqueFrameListsAfter.get(afterIndex));
					this.lostPacketIndics.addAll(this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketIndics());
					this.lostPacketLenTotal += this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketLenTotal();
					this.retransPacketIndics.addAll(this.uniqueFrameListsBefore.get(beforeIndex).getRetransPacketIndics());
					this.totalPacketNumber += this.uniqueFrameListsBefore.get(beforeIndex).getTotalPacketNumber();
					this.totalLossPacketNumber += this.uniqueFrameListsBefore.get(beforeIndex).getTotalLossPacketNumber();
					this.largestRetransmissionNum = Math.max(this.largestRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestRetransmissionNum());
					this.largestNoLossRetransRecovRetransmissionNum = Math.max(this.largestNoLossRetransRecovRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransRecovRetransmissionNum());
					this.largestNoLossRetransNoRecovRetransmissionNum = Math.max(this.largestNoLossRetransNoRecovRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestNoLossRetransNoRecovRetransmissionNum());
					this.largestLossRetransRetransmissionNum = Math.max(this.largestLossRetransRetransmissionNum, this.uniqueFrameListsBefore.get(beforeIndex).getLargestLossRetransRetransmissionNum());
					mergeRetransMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getRetransmissionMatrix());
					mergeNoLossRetransRecovMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransRecovRetransmissionMatrix());
					mergeNoLossRetransNoRecovMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getNoLossRetransNoRecovRetransmissionMatrix());
					mergelossRetransMatrix(this.uniqueFrameListsBefore.get(beforeIndex).getLossRetransRetransmissionMatrix());
					beforeIndex = beforeIndex + 1;
					afterIndex = afterIndex + 1;
				}
			}
		}
		Collections.sort(this.lostPacketIndics);
		Collections.sort(this.retransPacketIndics);
		caculatePacketLenInfo();
	}
	
	private void caculatePacketLenInfo(){
		for( int i= 0; i < this.uniqueFrameListsBefore.size(); i++){
			this.retransPacketLen += this.uniqueFrameListsBefore.get(i).getRetransPacketsLen();
			this.nonRetransPacketLen += this.uniqueFrameListsBefore.get(i).getNonRetransPacketsLen();
		}
	}
	
	private void mergeRetransMatrix( List<List<Long>> addMatrix){
		//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + ", this.largestRetransmissionNum = " + this.largestRetransmissionNum + ", addMatrix.size()" + addMatrix.size() + "\n");
		if (this.largestRetransmissionNum > this.retransmissionMatrix.size()){
			//System.out.println("this.largestRetransmissionNum - this.retransmissionMatrix.size() = " + (this.largestRetransmissionNum - this.retransmissionMatrix.size()) + "\n");
			int generateNum = this.largestRetransmissionNum - this.retransmissionMatrix.size();
			for ( int i = 0; i < generateNum; i ++){
				List<Long> generateList = new ArrayList<Long>();
				this.retransmissionMatrix.add(generateList);
				//System.out.println(i + "add one \n");
			}
			//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + "\n");
		}
		for ( int i = 0; i < addMatrix.size(); i ++ ){
			for ( int j = 0; j < addMatrix.get(i).size(); j ++ ){
				Long data = addMatrix.get(i).get(j);
				this.retransmissionMatrix.get(i).add(data);
			}
		}
	}
	
	private void mergeNoLossRetransRecovMatrix( List<List<Long>> addMatrix){
		//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + ", this.largestRetransmissionNum = " + this.largestRetransmissionNum + ", addMatrix.size()" + addMatrix.size() + "\n");
		if (this.largestNoLossRetransRecovRetransmissionNum > this.noLossRetransRecovRetransmissionMatrix.size()){
			//System.out.println("this.largestRetransmissionNum - this.retransmissionMatrix.size() = " + (this.largestRetransmissionNum - this.retransmissionMatrix.size()) + "\n");
			int generateNum = this.largestNoLossRetransRecovRetransmissionNum - this.noLossRetransRecovRetransmissionMatrix.size();
			for ( int i = 0; i < generateNum; i ++){
				List<Long> generateList = new ArrayList<Long>();
				this.noLossRetransRecovRetransmissionMatrix.add(generateList);
				//System.out.println(i + "add one \n");
			}
			//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + "\n");
		}
		for ( int i = 0; i < addMatrix.size(); i ++ ){
			for ( int j = 0; j < addMatrix.get(i).size(); j ++ ){
				Long data = addMatrix.get(i).get(j);
				this.noLossRetransRecovRetransmissionMatrix.get(i).add(data);
			}
		}
	}
	
	private void mergeNoLossRetransNoRecovMatrix( List<List<Long>> addMatrix){
		//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + ", this.largestRetransmissionNum = " + this.largestRetransmissionNum + ", addMatrix.size()" + addMatrix.size() + "\n");
		if (this.largestNoLossRetransNoRecovRetransmissionNum > this.noLossRetransNoRecovRetransmissionMatrix.size()){
			//System.out.println("this.largestRetransmissionNum - this.retransmissionMatrix.size() = " + (this.largestRetransmissionNum - this.retransmissionMatrix.size()) + "\n");
			int generateNum = this.largestNoLossRetransNoRecovRetransmissionNum - this.noLossRetransNoRecovRetransmissionMatrix.size();
			for ( int i = 0; i < generateNum; i ++){
				List<Long> generateList = new ArrayList<Long>();
				this.noLossRetransNoRecovRetransmissionMatrix.add(generateList);
				//System.out.println(i + "add one \n");
			}
			//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + "\n");
		}
		for ( int i = 0; i < addMatrix.size(); i ++ ){
			for ( int j = 0; j < addMatrix.get(i).size(); j ++ ){
				Long data = addMatrix.get(i).get(j);
				this.noLossRetransNoRecovRetransmissionMatrix.get(i).add(data);
			}
		}
	}
	
	private void mergelossRetransMatrix( List<List<Long>> addMatrix){
		//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + ", this.largestRetransmissionNum = " + this.largestRetransmissionNum + ", addMatrix.size()" + addMatrix.size() + "\n");
		if (this.largestLossRetransRetransmissionNum > this.lossRetransRetransmissionMatrix.size()){
			//System.out.println("this.largestRetransmissionNum - this.retransmissionMatrix.size() = " + (this.largestRetransmissionNum - this.retransmissionMatrix.size()) + "\n");
			int generateNum = this.largestLossRetransRetransmissionNum - this.lossRetransRetransmissionMatrix.size();
			for ( int i = 0; i < generateNum; i ++){
				List<Long> generateList = new ArrayList<Long>();
				this.lossRetransRetransmissionMatrix.add(generateList);
				//System.out.println(i + "add one \n");
			}
			//System.out.println("retransmissionMatrix.size() = "+ retransmissionMatrix.size() + "\n");
		}
		for ( int i = 0; i < addMatrix.size(); i ++ ){
			for ( int j = 0; j < addMatrix.get(i).size(); j ++ ){
				Long data = addMatrix.get(i).get(j);
				this.lossRetransRetransmissionMatrix.get(i).add(data);
			}
		}
	}
	
	/*public int getRtpNonSSRCNum(){
		return this.rtpNonSSRCNum;
	}
	
	public int getRtpSSRCNum(){
		return this.rtpSSRCNum;
	} 
	
	public int getNonRtpPacketNum(){
		return this.nonrtpPacketNum;
	}
	
	public long getRtpNonSSRCLen(){
		return this.rtpNonSSRCLen;
	}
	
	public long getRtpSSRCLen(){
		return this.rtpSSRCLen;
	} 
	
	public long getNonRtpPacketLen(){
		return this.nonrtpPacketLen;
	}*/
	
	public List<Long> getRtpNonSSRCLenList(){
		return this.rtpNonSSRCLenList;
	}
	
	public List<Long> getRtpSSRCLenList(){
		return this.rtpSSRCLenList;
	} 
	
	public List<Long> getNonRtpPacketLenList(){
		return this.nonrtpPacketLenList;
	}
	
	public long getRetransPacketLen(){
		return this.retransPacketLen;
	}
	
	public long getNonRetransPacketLen(){
		return this.nonRetransPacketLen;
	}
	
	public List<Integer> getRetransPacketIndics(){
		return this.retransPacketIndics;
	}
	public List<Integer> getLostPacketIndics(){
		return this.lostPacketIndics;
	} 
	public long getLostPacketLenTotal(){
		return this.lostPacketLenTotal;
	}
	//this.lostPacketLenTotal += this.uniqueFrameListsBefore.get(beforeIndex).getLostPacketLenTotal();
	
	public int getTotalPacketNumber(){
		return this.totalPacketNumber;
	}
	public int getTotalLossPacketNumber(){
		return this.totalLossPacketNumber;
	}
	public int getLargestRetransmissionNum(){
		return this.largestRetransmissionNum;
	} 
	public int getLargestNoLossRetransRecovRetransmissionNum(){
		return this.largestNoLossRetransRecovRetransmissionNum;
	} 
	public int getLargestNoLossRetransNoRecovRetransmissionNum(){
		return this.largestNoLossRetransNoRecovRetransmissionNum;
	} 
	public int getLargestLossRetransRetransmissionNum(){
		return this.largestLossRetransRetransmissionNum;
	}
	public List<Long> getRetransmissionTimeList(int i){
		if ( (i -1) < this.largestRetransmissionNum){
			List<Long> returnList = this.retransmissionMatrix.get(i-1);
			Collections.sort(returnList);
			return returnList;
		}else{
			return null;
		}
	}
	public List<Long> getNoLossRetransRecovRetransmissionList(int i){
		if ( (i -1) < this.largestNoLossRetransRecovRetransmissionNum){
			List<Long> returnList = this.noLossRetransRecovRetransmissionMatrix.get(i-1);
			Collections.sort(returnList);
			return returnList;
		}else{
			return null;
		}
	} 
	
	public List<Long> getNoLossRetransNoRecovRetransmissionList(int i){
		if ( (i -1) < this.largestNoLossRetransNoRecovRetransmissionNum){
			List<Long> returnList = this.noLossRetransNoRecovRetransmissionMatrix.get(i-1);
			Collections.sort(returnList);
			return returnList;
		}else{
			return null;
		}
	} 
	
	public List<Long> getLossRetransRetransmissionList(int i){
		if ( (i -1) < this.largestLossRetransRetransmissionNum){
			List<Long> returnList = this.lossRetransRetransmissionMatrix.get(i-1);
			Collections.sort(returnList);
			return returnList;
		}else{
			return null;
		}
	} 
}
