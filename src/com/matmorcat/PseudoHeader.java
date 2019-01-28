package com.matmorcat;

import static com.matmorcat.Segment.binaryToDecimal;
import static com.matmorcat.Segment.toBinaryIfHex;

/**
 * This class defines the pseudo-header object for the TCP/IP specifications.
 *
 * @author Matthew Moretz (mcmoretz@uncg.edu)
 */
public class PseudoHeader extends ConceptualObject {

    private String source, dest, reserved, protocol, segmentLength;


    // -------------------------------------------------------------------------
    //
    // Pseudo-Header Constructors
    //
    // -------------------------------------------------------------------------

    public PseudoHeader(String source, String dest, String protocol,
                        String segmentLength) throws Exception {

        this(source + dest + protocol + segmentLength);
    }

    public PseudoHeader(String data) throws Exception {

        String binary = toBinaryIfHex(data);

        // Process the data and parse individual fields
        setSourceField(binary.substring(0, 32));
        setDestField(binary.substring(32, 64));
        setReservedField(binary.substring(64, 72));
        setProtocolField(binary.substring(72, 80));
        setSegmentLengthField(binary.substring(80, 96));
    }

    public String getSourceField() {
        return source;
    }

    private void setSourceField(String source) throws Exception {

        // Check length of field
        if (source.length() != 32) {
            throw new Exception("Source address field must be 32 bits!");
        }

        this.source = source;
    }

    public String getDestField() {
        return dest;
    }

    private void setDestField(String dest) throws Exception {

        // Check length of field
        if (dest.length() != 32) {
            throw new Exception("Destination address field must be 32 bits!");
        }
        this.dest = dest;
    }

    public String getReservedField() {
        return reserved;
    }

    private void setReservedField(String reserved) throws Exception {

        // Check length of field
        if (reserved.length() != 8) {
            throw new Exception("Reserved field must be 8 bits!");
        }

        // Check length of field
        if (reserved.contains("1")) {
            throw new Exception("Pseudo-header reserved field must be all 0s!");
        }

        this.reserved = reserved;
    }

    public String getProtocolField() {
        return protocol;
    }

    private void setProtocolField(String protocol) throws Exception {

        // Check length of field
        if (protocol.length() != 8) {
            throw new Exception("Protocol field must be 8 bits!");
        }

        this.protocol = protocol;
    }

    public String getSegmentLengthField() {
        return segmentLength;
    }

    private void setSegmentLengthField(String segmentLength) throws Exception {

        // Check length of field
        if (segmentLength.length() != 16) {
            throw new Exception("Total length field must be 16 bits!");
        }

        this.segmentLength = segmentLength;
    }

    /**
     * Get the length of the segment minus the pseudo-header (from the
     * pseudo-header's TCP length field as a binary string.
     *
     * @return  the length of the TCP segment in binary
     */
    public int getSegmentLengthInBits() {
        return binaryToDecimal(getSegmentLengthField());
    }

    /**
     * The entire contents of the pseudo-header in binary.
     * @return  a continuous string of bits
     */
    public String bits() {
        return source + dest + reserved + protocol + segmentLength;
    }

    @Override
    public String toString() {
        return "PseudoHeader{" +
                "source='" + source + '\'' +
                ", dest='" + dest + '\'' +
                ", reserved='" + reserved + '\'' +
                ", protocol='" + protocol + '\'' +
                ", segmentLength='" + segmentLength + '\'' +
                '}';
    }
}
