package com.hicham.jnet;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;

@Header(suite = ProtocolSuite.TCP_IP,length=8)
public class OpenFlow extends JHeader{
	
	    @Field
		public String version;
		
	    public enum Type {

	    	Hello(0),
	        Error(1),
	        EchoRequest(2),
	        EchoReply(3),
	    	Vendor(4),
	    	FeaturesRequest(5),
	    	FeaturesReply(6),
	    	GetConfigRequest(7),
	    	GetConfigReply(8),
	    	SetConfig(9),
	    	PacketInputNotification(10),
	    	FlowRemovedNotification(11),
	    	PortStatusNotification(12),
	    	PacketOutput(13),
	    	FlowModification(14),
	    	PortModification(15),
	    	StatsRequest(16),
	    	StatsReply(17),
	    	BarrierRequest(18),
	    	BarrierReply(19);
	    	
	    	private final int type;
	    	Type(int type) {
				this.type = type;
			}
	    	
			@Field
			public int getType() {
				return type;
			}
		}
	    
	    
		@Field
	    public int lenght1;
		
		@Field
	    public int TransactionID;
		
		@Field
	    public String BUfferID;
		
		@Field
	    public int InPort;
		
		@Field
	    public int ActionsLenght;
		
	    public enum ActionsType{
	    	Output_to_switch_port (0);
	    	
	    	private final int actionsType;
	        ActionsType(int actionsType)
	    	{
	    		this.actionsType=actionsType;
	    	}
	        
	        @Field
			public int getActionsType() {
				return actionsType;
			}
	    }
	    
	    Type type;
	    ActionsType actionType;
	    
	    public int getType()
	    {
	    	return type.getType();
	    }
	    
	    public int getActionsType()
	    {
	    	return actionType.getActionsType();
	    }
		
		@Field
	    public int lenght2;
		
		@Field
	    public int OutputPort;
		
		@Field
	    public int MaxLenght;

}
