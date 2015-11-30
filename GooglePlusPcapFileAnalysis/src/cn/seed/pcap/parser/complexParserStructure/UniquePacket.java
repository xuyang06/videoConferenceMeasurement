package cn.seed.pcap.parser.complexParserStructure;
import java.util.*;

public class UniquePacket implements Comparable<UniquePacket>{
	private int sequenceNumber = -1;
	private long oriLength = -1;
	private List<Long> captureTimeList = new ArrayList<Long>();
	private boolean whetherLoss = false;
	private boolean NoLossNoRetrans = false;
	private boolean NoLossRetransRecov = false;
	private boolean LossNoRetrans = false;
	//private boolean retransmission = false; 
	public void setWhetherLoss(){
		if(whetherLoss == false){
			whetherLoss = true;
		}
	}
	
	public void checkNoLossInfo(UniquePacket otherPacket){
		if (this.sequenceNumber == otherPacket.sequenceNumber){
			if (!whetherLoss){
				if (this.captureTimeList.size() == 1){
					NoLossNoRetrans = true;
				}else{
					if (this.captureTimeList.size() > otherPacket.captureTimeList.size()){
						NoLossRetransRecov = true;
					}
				}
			}
		}
	}
	
	public boolean getWhetherLoss(){
		return this.whetherLoss;
	}
	
	public boolean whetherNoLossNoRetrans(){
		return this.NoLossNoRetrans;
	}
	
	public boolean whetherNoLossRetransRecov(){
		return this.NoLossRetransRecov;
	}
	
	public boolean whetherLossNoRetrans(){
		if (whetherLoss){
			if (this.captureTimeList.size() == 1){
				LossNoRetrans = true;
				return LossNoRetrans;
			}
		}
		LossNoRetrans = false;
		return LossNoRetrans;
	}
	
	public UniquePacket(int sequenceNumber, long captureTime, long oriLength){
		this.sequenceNumber = sequenceNumber;
		this.oriLength = oriLength;
		this.captureTimeList.add(captureTime);
	}
	
	public static void addUniquePacketToList(int sequenceNumber, long captureTime, long oriLength, List<UniquePacket> uniquePacketList){
		int havingPacketinList = 0;
		for (int i = 0; i < uniquePacketList.size(); i ++ ){
			if ( uniquePacketList.get(i).sequenceNumber == sequenceNumber){
				uniquePacketList.get(i).captureTimeList.add(captureTime);
				havingPacketinList = 1;
			}
		}
		if (havingPacketinList == 0){
			UniquePacket uniquePacket = new UniquePacket(sequenceNumber, captureTime, oriLength);
			uniquePacketList.add(uniquePacket);
		}
	}
	
	public int getSequenceNumber(){
		return this.sequenceNumber;
	}
	
	public List<Long> getRetransTimeInterval(){
		List<Long> retransTimeInterval = new ArrayList<Long>();
		if ( this.captureTimeList.size() > 1){
			for ( int i = 1; i < this.captureTimeList.size(); i ++){
				long timeInterval = this.captureTimeList.get(i) - this.captureTimeList.get(i-1);
				retransTimeInterval.add(timeInterval);
			}
		}
		return retransTimeInterval;
	}
	
	public List<Long> getCaptureTimeList(){
		return this.captureTimeList;
	}
	
	public long getOriLength(){
		return this.oriLength;
	}
	
	public int compareTo(UniquePacket otherPacket){
		Collections.sort(this.captureTimeList);
		Collections.sort(otherPacket.captureTimeList);
		if (this.sequenceNumber < otherPacket.sequenceNumber){
			return -1;
		}else if (this.sequenceNumber > otherPacket.sequenceNumber){
			return 1;
		}else{
			return 0;
		}
	}
}
