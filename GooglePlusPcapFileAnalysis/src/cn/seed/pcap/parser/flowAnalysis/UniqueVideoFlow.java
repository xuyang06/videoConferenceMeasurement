package cn.seed.pcap.parser.flowAnalysis;

public class UniqueVideoFlow {
	private int uniqueID = -1;
	private long totalLen = -1;
	private long durationTime = -1;
	private long startTime = -1;
	private long endTime = -1;
	private int count = 0;
	
	public UniqueVideoFlow(int ID, long packetLen, long time){
		if (this.uniqueID == -1){
			this.uniqueID = ID;
		}
		if (this.totalLen == -1){
			this.totalLen = packetLen;
		}
		if (this.startTime == -1){
			this.startTime = time;
			this.endTime = time;
		}
		if (this.count == 0){
			this.count = 1;
		}
	}
	
	public boolean existID( int ID){
		if (this.uniqueID == ID){
			return true;
		}
		return false;
	}
	
	public boolean addLen(int ID, long packetLen, long time){
		if (this.uniqueID == ID){
			this.totalLen = this.totalLen + packetLen;
			this.count = this.count + 1;
			this.endTime = time;
			return true;
		}
		return false;
	}
	
	public double getVideoFlowRate(){
		double flowRate = 0;		
		this.durationTime = this.endTime - this.startTime;
		if (this.durationTime != 0){
			flowRate = ( (double) this.totalLen )/ ( ( (double) this.durationTime )/1000000 );
		}
		return flowRate;
	}
	
	public int getUniqueID(){
		return this.uniqueID;
	}
	
	public int getTotalCount(){
		return this.count;
	}
	
}
