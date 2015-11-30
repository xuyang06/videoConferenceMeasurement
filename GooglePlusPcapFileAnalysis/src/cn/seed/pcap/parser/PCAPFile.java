package cn.seed.pcap.parser;

import java.util.ArrayList;
import java.util.List;

public class PCAPFile {
	public String filename = null;
	//public PCAPHeader header = null;
	public List<Package> packages = new ArrayList<Package>();
}
