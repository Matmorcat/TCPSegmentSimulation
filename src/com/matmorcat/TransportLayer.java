package com.matmorcat;

/**
 * This object defines the functional model of the Transport Layer for TCP/IP
 * specifications.
 *
 * @author Matthew Moretz (mcmoretz@uncg.edu)
 */
public class TransportLayer {

    //private String ipAddress;
    private Segment segment;

    public TransportLayer() {
        //setIpAddress(ipAddress);
    }

    public void pushSegment(TransportLayer receiver) throws Exception {

        // Push the segment to the receiving host
        receiver.pullSegment(getSegment());
    }

    private void pullSegment(Segment segment) throws Exception {

        // If the checksum of the received segment is not valid
        if (!segment.segmentHasValidChecksum()) {

            throw new Exception("Received segment does not have a valid " +
                    "checksum. The segment has been corrupted and will be " +
                    "discarded!");
        }
        // Set the current working segment to the received segment
        setSegment(segment);

    }
    public Segment getSegment() {
        return segment;
    }

    public void setSegment(Segment segment) throws Exception {

        // Generate a new checksum
        segment.generateNewChecksum();

        this.segment = segment;
    }
}
