package cn.seed.pcap.parser.complexParserStructure;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UniqueFrame implements Comparable<UniqueFrame>{
	private long generateTime = -1;
	private List<UniquePacket> packetsList = new ArrayList<UniquePacket>();
	private List<Integer> lostPacketIndics = new ArrayList<Integer>();
	private List<Long> lostPacketLenList = new ArrayList<Long>();
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
	public void getLostPacketInfo(UniqueFrame uniqueFrameAfter){
		for (int i = 0; i < this.packetsList.size(); i ++ ){
			if (this.packetsList.get(i).getCaptureTimeList().size() >1){
				this.retransPacketIndics.add(i+1);
			}
			if ( uniqueFrameAfter == null){
				lostPacketIndics.add(i+1);
				lostPacketLenList.add(this.packetsList.get(i).getOriLength());
				this.packetsList.get(i).setWhetherLoss();
			}else{
				if ( !receivePacketInFrame(uniqueFrameAfter, i)){
					lostPacketIndics.add(i+1);
					lostPacketLenList.add(this.packetsList.get(i).getOriLength());
					this.packetsList.get(i).setWhetherLoss();
				}
			}
			if (this.packetsList.get(i).getWhetherLoss()){
				if (this.packetsList.get(i).whetherLossNoRetrans() == false){
					largestLossRetransRetransmissionNum = Math.max(largestLossRetransRetransmissionNum, this.packetsList.get(i).getRetransTimeInterval().size());
				}
			}else{
				if (this.packetsList.get(i).whetherNoLossNoRetrans() == false){
					if ( this.packetsList.get(i).whetherNoLossRetransRecov()){
						largestNoLossRetransRecovRetransmissionNum = Math.max(largestNoLossRetransRecovRetransmissionNum, this.packetsList.get(i).getRetransTimeInterval().size());
					}else{
						largestNoLossRetransNoRecovRetransmissionNum = Math.max(largestNoLossRetransNoRecovRetransmissionNum, this.packetsList.get(i).getRetransTimeInterval().size());
					}
				}
			}
			largestRetransmissionNum = Math.max(largestRetransmissionNum, this.packetsList.get(i).getRetransTimeInterval().size());
		}
		getTotalNumber();
		if ( uniqueFrameAfter == null ){
			this.totalLossPacketNumber = this.totalPacketNumber;
		}else{
			this.totalLossPacketNumber = this.totalPacketNumber - uniqueFrameAfter.getTotalNumber();		
		}
		for ( int j = 0; j < this.largestRetransmissionNum; j ++){
			List<Long> generateList = new ArrayList<Long>();
			retransmissionMatrix.add(generateList);
		}
		for ( int j = 0; j < this.largestNoLossRetransRecovRetransmissionNum; j ++){
			List<Long> generateList = new ArrayList<Long>();
			noLossRetransRecovRetransmissionMatrix.add(generateList);
		}
		for ( int j = 0; j < this.largestNoLossRetransNoRecovRetransmissionNum; j ++){
			List<Long> generateList = new ArrayList<Long>();
			noLossRetransNoRecovRetransmissionMatrix.add(generateList);
		}
		for ( int j = 0; j < this.largestLossRetransRetransmissionNum; j ++){
			List<Long> generateList = new ArrayList<Long>();
			lossRetransRetransmissionMatrix.add(generateList);
		}
		for (int i = 0; i < this.packetsList.size(); i ++ ){
			for ( int j = 0; j < this.packetsList.get(i).getRetransTimeInterval().size(); j ++){
				retransmissionMatrix.get(j).add(this.packetsList.get(i).getRetransTimeInterval().get(j));
				if (this.packetsList.get(i).getWhetherLoss()){
					if (this.packetsList.get(i).whetherLossNoRetrans() == false){
						lossRetransRetransmissionMatrix.get(j).add(this.packetsList.get(i).getRetransTimeInterval().get(j));
					}
				}else{
					if (this.packetsList.get(i).whetherNoLossNoRetrans() == false){
						if ( this.packetsList.get(i).whetherNoLossRetransRecov()){
							noLossRetransRecovRetransmissionMatrix.get(j).add(this.packetsList.get(i).getRetransTimeInterval().get(j));
						}else{
							noLossRetransNoRecovRetransmissionMatrix.get(j).add(this.packetsList.get(i).getRetransTimeInterval().get(j));
						}
					}
				}
				if (this.packetsList.get(i).getRetransTimeInterval().get(j) > 500000){
					System.out.println(generateTime + " " + packetsList.get(i).getSequenceNumber() + " " + this.packetsList.get(i).getRetransTimeInterval().get(j) + " too long\n");
				}
			}
		}		
	}
	
	
	
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
	public List<Integer> getRetransPacketIndics(){
		return this.retransPacketIndics;
	}
	
	public List<Integer> getLostPacketIndics(){
		return this.lostPacketIndics;
	}
	
	public List<Long> getLostPacketLenList(){
		return this.lostPacketLenList;
	}
	
	public long getLostPacketLenTotal(){
		long lostPacketLenTotal = 0;
		for (int i = 0; i < this.lostPacketLenList.size(); i++){
			lostPacketLenTotal += this.lostPacketLenList.get(i);
		}
		return lostPacketLenTotal;
	}
	
	public List<List<Long>> getRetransmissionMatrix(){
		return this.retransmissionMatrix;
	}
	
	public List<List<Long>> getNoLossRetransRecovRetransmissionMatrix(){
		return this.noLossRetransRecovRetransmissionMatrix;
	} 
	public List<List<Long>> getNoLossRetransNoRecovRetransmissionMatrix(){
		return this.noLossRetransNoRecovRetransmissionMatrix;
	} 
	public List<List<Long>> getLossRetransRetransmissionMatrix(){
		return this.lossRetransRetransmissionMatrix;
	} 
	
	private int getTotalNumber(){
		if (totalPacketNumber == -1){
			totalPacketNumber = 0;
			for (int i = 0; i < this.packetsList.size(); i ++ ){
				totalPacketNumber += this.packetsList.get(i).getCaptureTimeList().size();						
			}
		}
		return totalPacketNumber;
	}
	
	private boolean receivePacketInFrame(UniqueFrame frame, int j){
		for (int i = 0; i < frame.packetsList.size(); i ++){
			if ( this.packetsList.get(j).getSequenceNumber()== frame.packetsList.get(i).getSequenceNumber()){
				this.packetsList.get(j).checkNoLossInfo(frame.packetsList.get(i));
				return true;
			}
		}
		return false;
	}
	
	public UniqueFrame(long generateTime, int sequenceNumber, long captureTime, long oriLength){
		this.generateTime = generateTime;
		UniquePacket uniquePacket = new UniquePacket(sequenceNumber, captureTime, oriLength);
		this.packetsList.add(uniquePacket);
		System.out.println("generateTime" + generateTime + "\n");
	}
	
	public static void addUniqueFrameToList(long generateTime, int sequenceNumber, long captureTime, long oriLength, List<UniqueFrame> uniqueFrameList){
		int havingFrameInList = 0;
		for(int i = 0; i < uniqueFrameList.size(); i++){
			if (uniqueFrameList.get(i).generateTime == generateTime){
				UniquePacket.addUniquePacketToList(sequenceNumber, captureTime, oriLength, uniqueFrameList.get(i).packetsList);
				havingFrameInList = 1;
			}
		}
		if ( havingFrameInList == 0){
			UniqueFrame uniqueFrame = new UniqueFrame(generateTime, sequenceNumber, captureTime, oriLength);
			uniqueFrameList.add(uniqueFrame);
		}
	}
	
	public long getGenerateTime(){
		return this.generateTime;
	}
	
	public List<UniquePacket> getPacketsList(){
		return this.packetsList;
	}
	
	public int compareTo(UniqueFrame otherFrame){
		Collections.sort(this.packetsList);
		Collections.sort(otherFrame.packetsList);
		if ( this.generateTime == otherFrame.generateTime){
			return 0;
		}else if ( this.generateTime < otherFrame.generateTime ){
			return -1;
		}else{
			return 1;
		}
	}
	
	public int compare(UniqueFrame otherFrame){
		if ( this.generateTime == otherFrame.generateTime){
			return 0;
		}else if ( this.generateTime < otherFrame.generateTime ){
			return -1;
		}else{
			return 1;
		}	
	}
	
	public long getRetransPacketsLen(){
		long retransPacketLen = 0;
		for (int i = 0; i < this.packetsList.size(); i ++ ){
			if (this.packetsList.get(i).getCaptureTimeList().size() >1){
				retransPacketLen += this.packetsList.get(i).getOriLength()* (this.packetsList.get(i).getCaptureTimeList().size() -1 );
			}
		}
		return retransPacketLen;
	}
	
	public long getNonRetransPacketsLen(){
		long nonRetransPacketLen = 0;
		for (int i = 0; i < this.packetsList.size(); i ++ ){
			/*if (this.packetsList.get(i).getCaptureTimeList().size() ==1){
				nonRetransPacketLen += this.packetsList.get(i).getOriLength();
			}*/
			nonRetransPacketLen += this.packetsList.get(i).getOriLength();
		}
		return nonRetransPacketLen;
	}
	
}
