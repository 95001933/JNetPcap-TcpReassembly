package com.hicham.jnet;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.analysis.AbstractAnalyzer;
import org.jnetpcap.packet.analysis.AnalysisException;
import org.jnetpcap.packet.analysis.AnalyzerListener;
import org.jnetpcap.packet.analysis.FragmentAssembly;
import org.jnetpcap.packet.analysis.FragmentAssemblyEvent;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.packet.analysis.ProtocolSupport;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.TcpAssembler;
import org.jnetpcap.protocol.tcpip.TcpSequencer;
import org.jnetpcap.util.JThreadLocal;

public class OpenFlowAnalyzer extends AbstractAnalyzer implements AnalyzerListener<FragmentAssemblyEvent> {

	private JThreadLocal<OpenFlow> OpenFlowLocal = new JThreadLocal<OpenFlow>(OpenFlow.class);
	private JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);
    private TcpSequencer tcpFragAnalyzer = (TcpSequencer)JRegistry.getAnalyzer(TcpSequencer.class);
    private TcpAssembler tcpReassAnalyzer = (TcpAssembler)JRegistry.getAnalyzer(TcpAssembler.class);
    
    private final ProtocolSupport<OpenFlowHandler, OpenFlow> support = new ProtocolSupport<OpenFlowHandler,OpenFlow>()
    {
      @Override
      public void dispatch(OpenFlowHandler handler, OpenFlow openflow)
      {
        handler.processOpenFlow(openflow);
      }

    };
    
    OpenFlow userOpenFlow;
    public OpenFlowAnalyzer()
    {
      super();

      ((JController)JRegistry.getAnalyzer(JController.class)).addAnalyzer(this, JRegistry.lookupId(OpenFlow.class));

      this.tcpReassAnalyzer.addReassemblyListener(this, null);
    }

    
    
	@Override
	public boolean processPacket(JPacket packet) throws AnalysisException {
		// TODO Auto-generated method stub
		OpenFlow openFlow = (OpenFlow)this.OpenFlowLocal.get();
		
		if (packet.hasHeader(openFlow)) {
		      processOpenFlow(packet,openFlow);
		    }

		    return true;
	}



	private void processOpenFlow(JPacket packet, OpenFlow openFlow) {
		// TODO Auto-generated method stub
	    Tcp tcp = (Tcp)this.tcpLocal.get();
        if((packet.hasHeader(openFlow)) && (packet.hasHeader(tcp)))
        {
        	int tcp_len = tcp.getPayloadLength();
            int content_len = openFlow.lenght1;
            int openflow_len = content_len + openFlow.size();
            if (tcp_len >= openflow_len) {
                userOpenFlow = (OpenFlow)packet.getHeader(new OpenFlow());
                this.support.fire(userOpenFlow);
              }
              else {
                  this.tcpFragAnalyzer.setFragmentationBoundary(tcp.uniHashCode(), tcp.seq(), openflow_len);
              }
           
        }
	}


	public boolean add(OpenFlowHandler o)
	  {
	    return this.support.add(o);
	  }

	  public boolean remove(OpenFlowHandler o) {
	    return this.support.remove(o);
	  }


	@Override
	public void processAnalyzerEvent(FragmentAssemblyEvent evt) {
		// TODO Auto-generated method stub
		if (evt.getType() == FragmentAssemblyEvent.Type.COMPLETE_PDU) {
		      FragmentAssembly assembly = evt.getAssembly();
		      JPacket packet = assembly.getPacket();
		      OpenFlow openflow = new OpenFlow();
		      if (packet.hasHeader(openflow))
		          this.support.fire(openflow);
		        else
		          throw new IllegalStateException("expected OpenFlow packet");
		}
	}



	public ProtocolSupport<OpenFlowHandler, OpenFlow> getSupport() {
		return support;
	}

}
