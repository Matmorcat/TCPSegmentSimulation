package com.matmorcat;

/**
 * This allows you to simulate the passing of data in the form of a hexadecimal string to be assembled into a TCP segment.
 *
 * @author Matthew Moretz (mcmoretz@uncg.edu)
 */
public class Main {
        
    // Time between showing steps of process (in seconds)
    final static double PROCESS_WAIT_IN_SECONDS = 1.5;
    
    final static String PREFIX = "[Transport Layer]: ";
    
    private static String dataToTransmit;
    
    public static void main(String[] args) throws Exception {
        dataToTransmit =
                "AAAA995555555555000600E012C45678FFFFFFFFBBBBBBBB603F1B3472345E551D341234F2345678";

        // Define the transport layer for the sending and receiving host
        TransportLayer sender = new TransportLayer();
        TransportLayer receiver = new TransportLayer();
        
        
        System.out.println(PREFIX + "Inputting data \"" + dataToTransmit + "\"\n");
        waitStep();

        // Input the data into the transport layer
        sender.setSegment(new Segment(dataToTransmit));
        sender.getSegment().generateNewChecksum();
        waitStep();
        
        System.out.println(PREFIX + "The segment being sent...\n");
        System.out.println(sender.getSegment().toString() + "\n");
        waitStep();
        
        /*
        Pass the segment through the network

        This is where the Transport Layer would receive it, but for this assignment,
        the data would just be sent to the receiver's Transport Layer to be unpacked

        Segment will be received by receiving host
        */
        sender.pushSegment(receiver);
        
        System.out.println(PREFIX + "The received segment ...\n");
        System.out.println(receiver.getSegment().toString() + "\n");
    }
    
    
    public static void waitStep() {
        try {
            
            Thread.sleep((int) (1000 * PROCESS_WAIT_IN_SECONDS));
            
        } catch(InterruptedException e) {
            
            Thread.currentThread().interrupt();
        }
    }
}
