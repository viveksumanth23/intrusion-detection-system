Skip to content
Search or jump to…

Pull requests
Issues
Marketplace
Explore
 
@viveksumanth23 
Learn Git and GitHub without any code!
Using the Hello World guide, you’ll start a branch, write comments, and open a pull request.


0
01naitik0212/Java-Projects
 Code Issues 0 Pull requests 0 Projects 0 Wiki Security Insights
Java-Projects/Intrusion Detection System/ntalfinal.java
@naitik0212 naitik0212 Intrusion Detection System
73c0293 on Sep 5, 2017
Executable File  546 lines (353 sloc)  13.8 KB
  
import jpcap.*;
import jpcap.NetworkInterface;
import jpcap.JpcapCaptor;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import java.util.*;
import java.io.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;



class sniffer implements PacketReceiver {
	
	static String content1 =new String();
	static String content2 =new String();
	static String content3 =new String();
	static String content4 =new String();
	static String content5 =new String();
	
    static int i = 0,count=0;
    String protocoll[] = {"HOPOPT", "ICMP", "IGMP", "GGP", "IPV4", "ST", "TCP", "CBT", "EGP", "IGP", "BBN", "NV2", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "mux"};
    private NetworkInterface[] devices;
    
    
    
    
    
    

    public void receivePacket(Packet packet) {
    	
    	
    	
    	
    	
        /*try {
			String content =new String();
			File file = new File("reportSignature.txt");
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.append("\n ***report*** \n ");
		
			bw.close();
			System.out.println("Done");
		} catch (IOException e) {
			e.printStackTrace();
		}
    */
    	
    	
    	
        System.out.println(packet + "\n");
        System.out.println("this is packet " + i + " :" + "\n");
        i++;

      IPPacket tpt=(IPPacket)packet;
 if (packet != null) {

int ppp=tpt.protocol;
String proto=protocoll[ppp];
System.out.println("about the ip packet in network layer : \n");
System.out.println("******************************************************************");
if(tpt.dont_frag){
    System.out.println("dft bi is set. packet will not be fragmented \n");

}else{
    System.out.println("dft bi is not set. packet will  be fragmented \n");
}
System.out.println(" \n destination ip is :"+tpt.dst_ip);
System.out.println("\n this is source ip :"+tpt.src_ip);
System.out.println("\n this is hop limit :"+tpt.hop_limit);
System.out.println(" \n this is identification field  :"+tpt.ident);
System.out.println(" \npacket length :"+tpt.length);
System.out.println("\n packet priority  :"+(int)tpt.priority);
System.out.println("type of service field"+tpt.rsv_tos);
if(tpt.r_flag){
    System.out.println("releiable transmission");
}else{
    System.out.println("not reliable");
    
    
    
    
  try {

			//String content1 =new String();
			

			File file = new File("Unreliable.txt");
			
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			content1=tpt.src_ip.toString();
			bw.append(content1);
			bw.append("\n");
			bw.append("***report***");

			bw.append("this is unreliable connection.");
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}

    
    
}
System.out.println("protocol version is : "+(int)tpt.version);
System.out.println("flow label field"+tpt.flow_label);

System.out.println("**********************************************************************");

System.out.println("datalink lavel analysis");
System.out.println("********************************************************************");
 DatalinkPacket dp = packet.datalink;


            EthernetPacket ept=(EthernetPacket)dp;
            System.out.println("this is destination mac address :"+ept.getDestinationAddress());
            System.out.println("\n this is source mac address"+ept.getSourceAddress());
            


System.out.println("*********************************************************************");
System.out.println("this is about type of packet");
System.out.println("******************************************************************************");
              
                if (proto.equals(("TCP"))) {
                    System.out.println(" /n this is TCP packet");
                    TCPPacket tp = (TCPPacket) packet;
                    System.out.println("this is destination port of tcp :" + tp.dst_port);
                    if (tp.ack) {
                        System.out.println("\n" + "this is an acknowledgement");
                    } else {
                        System.out.println("this is not an acknowledgment packet");
                    }

                    if (tp.rst) {
                        System.out.println("reset connection ");
                    }
                    System.out.println(" \n protocol version is :" + tp.version);
                    System.out.println("\n this is destination ip " + tp.dst_ip);
                    System.out.println("this is source ip"+tp.src_ip);
                    
                  count++;

                    
          try {

			//String content2 =new String();
			

			File file = new File("reportTCP.txt");

			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
		int x=0;
			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			  content2=tp.src_ip.toString();
			  bw.append("***report***");

			bw.write(content2);
			if((content2.charAt(1)=='2')&&(content2.charAt(2)>='4'))
			{
				bw.append("\n this is signature based attack by ip address of class E");
				bw.append((char)count);
			}
			if(content2.charAt(1)=='2')
			{
				bw.append("this is signature based attack type of class D");
				bw.append((char)count);
			}
			
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}
                    
                    
                    
                   if(tp.fin){
                       System.out.println("sender does not have more data to transfer");
                   }
                    if(tp.syn){
                        System.out.println("\n request for connection");
                        
                        
                        
                        
                           try {

			//String content3 =new String();
			

			File file = new File("reportSync.txt");

			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			  content3=tp.src_ip.toString();
			  bw.append("***report***");

			bw.write(content3);
			
			
				bw.append("This is Synflood attack.  \n this is a type of denial of service attack");
			
			
			
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}
                        
                        
                        
                        
                        
                    }

                }else if(proto.equals("ICMP")){
                    ICMPPacket ipc=(ICMPPacket)packet;
             // java.net.InetAddress[] routers=ipc.router_ip;
              //for(int t=0;t
                //  System.out.println("\n"+routers[t]);
             // }
              System.out.println(" \n this is alive time :"+ipc.alive_time);
              System.out.println("\n number of advertised address :"+(int)ipc.addr_num);
              System.out.println("mtu of the packet is :"+(int)ipc.mtu);
              System.out.println("subnet mask :"+ipc.subnetmask);
              System.out.println("\n source ip :"+ipc.src_ip);
              System.out.println("\n destination ip:"+ipc.dst_ip);
              System.out.println("\n check sum :"+ipc.checksum);
              System.out.println("\n icmp type :"+ipc.type);
              System.out.println("");
              
              
              
            
               try {

			//String content4 =new String();
			

			File file = new File("reportICMP.txt");

		//	if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			 content4=ipc.src_ip.toString();
			 if(ipc.type!=2)
			 {
			bw.append("\n ***report*** \n");	
			bw.append("Anomoly detected. Anomoly based attack\n");
			bw.append(content4);
	}
			bw.close();

			System.out.println("Done");

	} catch (IOException e) {
			e.printStackTrace();
		}


                }else if(proto.equals("UDP")){
                    UDPPacket pac=(UDPPacket)packet;
                    System.out.println("this is udp packet \n");
                    System.out.println("this is source port :"+pac.src_port);
                    System.out.println("this is destination port :"+pac.dst_port);
                    
                    
                    
                    
                     try {

			
			

			File file = new File("reportUDP.txt");

		//	if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			 //content=pac.src_port.toString();
			 int x=pac.src_port;
			 if(x==137)
			 {
			bw.write("\n ***report*** \n");	
			bw.write("Dangerous port.\n");
			bw.append("137");
	}
			bw.close();

			System.out.println("Done");

	} catch (IOException e) {
			e.printStackTrace();
		}



                   
                    

                }

              System.out.println("******************************************************");

            }




        }

    

    public static void main(String str[]) throws Exception {
    	
    	
    	
    	
    	
    	
  JFrame frame = new JFrame("Test");
  frame.setVisible(true);
  frame.setSize(500,200);
  frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

  JPanel panel = new JPanel();
  frame.add(panel);
  JButton button = new JButton("UNRELIABLE CONNECTION");
  panel.add(button);
  button.addActionListener (new Action1());

  JButton button2 = new JButton("REPORT TCP");
  panel.add(button2);
  button.addActionListener (new Action2()); 
  
  JButton button3 = new JButton("REPORT SYNC");
  panel.add(button3);
  button.addActionListener (new Action3()); 
  
  JButton button4 = new JButton("REPORT ICMP");
  panel.add(button4);
  button.addActionListener (new Action4()); 
  
  JButton button5 = new JButton("REPORT UDP");
  panel.add(button5);
  button.addActionListener (new Action5()); 
  
    	
    	
    	
    	
    	
    	
    	
    	
    	
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        

        for (int i = 0; i <devices.length; i++) 
        {
            System.out.println(i + " :" + devices[i].name + "(" + devices[i].description + ")");
            System.out.println("    data link:" + devices[i].datalink_name + "("
                    + devices[i].datalink_description + ")");
            System.out.print("    MAC address:");
            for (byte b : devices[i].mac_address) {
               System.out.print(Integer.toHexString(b & 0xff) + ":");
            }
            System.out.println();
            for (NetworkInterfaceAddress a : devices[i].addresses) {


                System.out.println("    address:" + a.address + " " + a.subnet + " "
                        + a.broadcast);



		




  try {

			String content =new String();
			

			File file = new File("received.txt");

			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			content=a.address.toString();
			bw.append(content);
		
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}






            }
        }

        JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[0], 2000, true, 20);

        jpcap.loopPacket(-1, new sniffer());
    }

   
   
   static class Action1 implements ActionListener {        
  public void actionPerformed (ActionEvent e) {     
    JFrame frame2 = new JFrame("THE CONNECTION IS UNRELIABLE");
    frame2.setVisible(true);
    frame2.setSize(500,200); 
  
    JLabel label = new JLabel(content1);
    JPanel panel = new JPanel();
    frame2.add(panel);
    panel.add(label);       
  }
}   
static class Action2 implements ActionListener {        
  public void actionPerformed (ActionEvent e) {     
    JFrame frame3 = new JFrame("REPORT TCP");
    frame3.setVisible(true);
    frame3.setSize(500,200);
    JLabel label = new JLabel("THIS IS A SIGNATURE BASED ATTACK");
	 JLabel label1 = new JLabel(content2);

    JPanel panel = new JPanel();
    frame3.add(panel);
    panel.add(label);
    panel.add(label1);
  }
}   

static class Action3 implements ActionListener {        
  public void actionPerformed (ActionEvent e) {     
    JFrame frame4 = new JFrame("REPORT SYNC");
    frame4.setVisible(true);
    frame4.setSize(500,200);
    JLabel label = new JLabel("TRYING TO FLOOD WITH SYNC BIT");
     JLabel label2 = new JLabel(content3);

    JPanel panel = new JPanel();
    frame4.add(panel);
    panel.add(label);
    panel.add(label2);       
  }
}

static class Action4 implements ActionListener {        
  public void actionPerformed (ActionEvent e) {     
    JFrame frame5 = new JFrame("ICMP TYPE");
    frame5.setVisible(true);
    frame5.setSize(500,200);
    JLabel label = new JLabel("This is anomaly attack(change in state)");
    JLabel label3 = new JLabel(content4);
    JPanel panel = new JPanel();
    frame5.add(panel);
    panel.add(label); 
    panel.add(label3);      
  }
}


static class Action5 implements ActionListener {        
  public void actionPerformed (ActionEvent e) {     
    JFrame frame6 = new JFrame("UDPTYPE");
    frame6.setVisible(true);
    frame6.setSize(500,200);
    JLabel label = new JLabel("TRYING TO ACCESS PRIVATE PORT");
     JLabel label4 = new JLabel(content5);

    JPanel panel = new JPanel();
    frame6.add(panel);
    panel.add(label);  
    panel.add(label4);     
  }
}
}



