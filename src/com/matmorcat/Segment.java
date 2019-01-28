package com.matmorcat;


/**
 * This is an object class that defines the structure of a TCP segment and
 * provides necessary methods to encapsulate fields of the segment and check
 * it for validity. This object also inherits the pseudo-header which is used
 * by the Network Layer to assemble the datagram, but is included in the
 * Transport Layer in order to calculate the checksum.
 *
 * The program is based on the internet standard proposed in RFC 793 - "Transmission Control Protocol"
 * The document can be viewed here for reference: https://tools.ietf.org/html/rfc793
 * 
 * @author Matthew Moretz (mcmoretz@uncg.edu)
 */
public final class Segment {
    
    // The length of the pseudo-header in bits is always 96 for TCP
    private static final int PSEUDO_HEADER_LENGTH_IN_BIT = 96;

    // Enumerations for flags to make code more easily readable
    private static final int URG_FLAG_INDEX = 0;
    private static final int ACK_FLAG_INDEX = 1;
    private static final int PSH_FLAG_INDEX = 2;
    private static final int RST_FLAG_INDEX = 3;
    private static final int SYN_FLAG_INDEX = 4;
    private static final int FIN_FLAG_INDEX = 5;

    // State enumerations for readability
    private static final char STATE_FALSE = '0';
    private static final char STATE_TRUE = '1';
    
    private PseudoHeader pseudoHeader;
    
    private String sourcePort, destPort, sequence, ack, headerLength, 
    reserved, flags, window, checksum, urgentPointer, options, payload;

    
    // -------------------------------------------------------------------------
    //
    // Segment Constructors
    //
    // -------------------------------------------------------------------------


    /**
     * Takes in the contents of a segment and assembles an object from the data.
     * Each bit of information is checked for validity. Hexadecimal and binary are
     * accepted inputs, so long as they adhere to the TCP/IP specifications.
     * An error message will be thrown describing what input is invalid if an
     * invalid input is detected.
     *
     * @param sourcePort    the port bound to the sending application
     * @param destPort      the port of the receiving application
     * @param sequence      the sequence number of the sender
     * @param ack           the acknowledgement number of the receiver's
     *                      sequence number
     * @param headerLength  the length of the TCP header (32-bit words)
     * @param reserved      reserved for future use and must be all 0s
     * @param flags         the control flags for transmission
     * @param window        the window size that sender is willing to receive
     *                      back (octets)
     * @param checksum      the checksum of the pseudo-header + TCP header +
     *                      payload concatenated
     * @param urgentPointer the location of any urgent data from the application
     *                      starting at the first byte of data (octets)
     * @param options       the options (if any) to include, such as security clearance
     * @param payload       the data that is to be transmitted in the segment
     *
     * @throws Exception    the segment could not be created, because one or
     * more inputs were invalid
     */
    public Segment(String sourcePort, String destPort, String sequence, String ack, 
                   String headerLength, String reserved, String flags, String window, 
                   String checksum, String urgentPointer, String options, 
                   String payload) throws Exception {

        this(sourcePort + destPort + sequence + ack + headerLength + reserved
                + flags + window + checksum + urgentPointer + options + payload);
    }

    /**
     * Takes in the contents of a segment and assembles an object from the data.
     * Each bit of information is checked for validity. Hexadecimal and binary are
     * accepted inputs, so long as they adhere to the TCP/IP specifications.
     * An error message will be thrown describing what input is invalid if an
     * invalid input is detected.
     *
     * @param data          the data that is to be transmitted in the segment
     * @throws Exception    the segment could not be created, because one or
     * more inputs were invalid
     */
    public Segment(String data) throws Exception {
        String binary = toBinaryIfHex(data);

        // Process and create the pseudo-header with the data given
        setPseudoHeader(new PseudoHeader(binary.substring(0, PSEUDO_HEADER_LENGTH_IN_BIT)));
        
        // Parse individual TCP segment fields with fixed lengths
        setSourcePortField(     binary.substring(0 + PSEUDO_HEADER_LENGTH_IN_BIT, 16 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setDestPortField(       binary.substring(16 + PSEUDO_HEADER_LENGTH_IN_BIT, 32 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setSequenceField(       binary.substring(32 + PSEUDO_HEADER_LENGTH_IN_BIT, 64 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setAckField(            binary.substring(64 + PSEUDO_HEADER_LENGTH_IN_BIT, 96 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setHeaderLengthField(   binary.substring(96 + PSEUDO_HEADER_LENGTH_IN_BIT, 100 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setReservedField(       binary.substring(100 + PSEUDO_HEADER_LENGTH_IN_BIT, 106 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setFlagsField(          binary.substring(106 + PSEUDO_HEADER_LENGTH_IN_BIT, 112 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setWindowField(         binary.substring(112 + PSEUDO_HEADER_LENGTH_IN_BIT, 128 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setChecksumField(       binary.substring(128 + PSEUDO_HEADER_LENGTH_IN_BIT, 144 + PSEUDO_HEADER_LENGTH_IN_BIT));
        setUrgentPointerField(  binary.substring(144 + PSEUDO_HEADER_LENGTH_IN_BIT, 160 + PSEUDO_HEADER_LENGTH_IN_BIT));
        
        // Check that the length of the data inputted matches the total length field value in bits
        if (binary.length() != PSEUDO_HEADER_LENGTH_IN_BIT
                + getPseudoHeader().getSegmentLengthInBits()) {
        
            throw new Exception("Segment is incomplete or TCP length field in" +
                    " the pseudo-header data is invalid!");
        }
        
        // Check that the length of the header data and/or payload data is of the right length
        else if (getPayloadLengthInBits() < 8) {
        
            throw new Exception("Segment is incomplete or header length field is invalid!");
        }
        
        // Process the data and parse individual fields with variable length
        setOptionsField(binary.substring(160 + PSEUDO_HEADER_LENGTH_IN_BIT, 
                160 + PSEUDO_HEADER_LENGTH_IN_BIT + getOptionsLengthInBits()));
        setPayloadField(binary.substring(160 + PSEUDO_HEADER_LENGTH_IN_BIT
                + getOptionsLengthInBits(), PSEUDO_HEADER_LENGTH_IN_BIT
                + getTotalLengthInBits()));
    }

    
    // -------------------------------------------------------------------------
    //
    // Segment Field Getter & Setter Methods
    //
    // -------------------------------------------------------------------------

    public PseudoHeader getPseudoHeader() {
        return pseudoHeader;
    }

    public void setPseudoHeader(PseudoHeader pseudoHeader) {
        this.pseudoHeader = pseudoHeader;
    }
    
    public String getSourcePortField() {
        return sourcePort;
    }

    private void setSourcePortField(String sourcePort) throws Exception {

        // Check length of field
        if (sourcePort.length() != 16) {
            throw new Exception("Source port field must be 16 bits!");
        }

        this.sourcePort = sourcePort;
    }

    public String getDestPortField() {
        return destPort;
    }

    private void setDestPortField(String destPort) throws Exception {

        // Check length of field
        if (destPort.length() != 16) {
            throw new Exception("Destination port field must be 16 bits!");
        }

        this.destPort = destPort;
    }

    public String getSequenceField() {
        return sequence;
    }

    private void setSequenceField(String sequence) throws Exception {

        // Check length of field
        if (sequence.length() != 32) {
            throw new Exception("Sequence number field must be 32 bits!");
        }

        this.sequence = sequence;
    }

    public String getAckField() {
        return ack;
    }

    private void setAckField(String ack) throws Exception {

        // Check length of field
        if (ack.length() != 32) {
            throw new Exception("Acknowledgment number field must be 32 bits!");
        }

        this.ack = ack;
    }

    public String getHeaderLengthField() {
        return headerLength;
    }

    private void setHeaderLengthField(String headerLength) throws Exception {

        // Check length of field
        if (headerLength.length() != 4) {
            throw new Exception("Header length field must be 4 bits!");
        }

        this.headerLength = headerLength;
    }

    public String getReservedField() {
        return reserved;
    }

    private void setReservedField(String reserved) throws Exception {

        // Check length of field
        if (reserved.length() != 6) {
            throw new Exception("Reserved field must be 6 bits!");
        }

        // Check length of field
        if (reserved.contains("1")) {
            throw new Exception("TCP header reserved field must be all 0s!");
        }

        this.reserved = reserved;
    }

    public String getFlagsField() {
        return flags;
    }

    private void setFlagsField(String flags) throws Exception {

        // Check length of field
        if (flags.length() != 6) {
            throw new Exception("Control flags field must be 6 bits!");
        }

        this.flags = flags;
    }

    public String getWindowField() {
        return window;
    }

    private void setWindowField(String window) throws Exception {

        // Check length of field
        if (window.length() != 16) {
            throw new Exception("Window size field must be 16 bits!");
        }

        this.window = window;
    }

    public String getChecksumField() {
        return checksum;
    }

    private void setChecksumField(String checksum) throws Exception {

        // Check length of field
        if (checksum.length() != 16) {
            throw new Exception("Checksum field must be 16 bits!");
        }

        this.checksum = checksum;
    }

    public String getUrgentPointerField() {
        return urgentPointer;
    }

    private void setUrgentPointerField(String urgentPointer) throws Exception {

        // Check length of field
        if (urgentPointer.length() != 16) {
            throw new Exception("Urgent Pointer field must be 16 bits!");
        }

        // Check that the urgent control flag is set
        if (!getFlagUrgent()) {
            throw new Exception("Urgent control flag must be set!");
        }

        this.urgentPointer = urgentPointer;
    }

    public String getOptionsField() {
        return options;
    }

    private void setOptionsField(String options) {

        // Make sure the options is padded up to 32-bit length
        this.options = padRightToLength(options, 32);
    }

    public String getPayloadField() {
        return payload;
    }

    private void setPayloadField(String payload) {
        this.payload = payload;
    }


    // -------------------------------------------------------------------------
    //
    // Getters & Setters for Control Flags
    //
    // -------------------------------------------------------------------------


    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagUrgent() {
        return getFlagsField().charAt(URG_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagUrgent(boolean newState) throws Exception {
        setFlagAtPosition(URG_FLAG_INDEX, newState);
    }

    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagAcknowledgment() {
        return getFlagsField().charAt(ACK_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagAcknowledgment(boolean newState) throws Exception {
        setFlagAtPosition(ACK_FLAG_INDEX, newState);
    }

    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagPush() {
        return getFlagsField().charAt(PSH_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagPush(boolean newState) throws Exception {
        setFlagAtPosition(PSH_FLAG_INDEX, newState);
    }

    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagReset() {
        return getFlagsField().charAt(RST_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagReset(boolean newState) throws Exception {
        setFlagAtPosition(RST_FLAG_INDEX, newState);
    }

    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagSynchonize() {
        return getFlagsField().charAt(SYN_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagSynchonize(boolean newState) throws Exception {
        setFlagAtPosition(SYN_FLAG_INDEX, newState);
    }

    /**
     * A method to get the state of this flag.
     *
     * @return  the state of the flag
     */
    public boolean getFlagFinal() {
        return getFlagsField().charAt(FIN_FLAG_INDEX) == STATE_TRUE;
    }

    /**
     * A method to set the state of this flag.
     *
     * @param newState      the state to set it to
     * @throws Exception    if there was an error changing the flag
     */
    private void setFlagFinal(boolean newState) throws Exception {
        setFlagAtPosition(FIN_FLAG_INDEX, newState);
    }

    /**
     * This method takes in the index of a flag in relation to the flags
     * field and changes it to a new state. See the indexes below for reference:
     *
     *  URG:  Urgent Pointer field significant  = 0
     *  ACK:  Acknowledgment field significant  = 1
     *  PSH:  Push Function                     = 2
     *  RST:  Reset the connection              = 3
     *  SYN:  Synchronize sequence numbers      = 4
     *  FIN:  No more data from sender          = 5
     *
     *  (Flag source: https://tools.ietf.org/html/rfc793#page-16)
     *
     * @param index         the index of the flag to set
     * @param newState      the state (true or false) to set the flag to
     * @throws Exception    if an error is encountered setting the flags
     */
    private void setFlagAtPosition(int index, boolean newState) throws Exception {

        // Check to make sure that the index is within bounds of the flag field
        if (index < 0 || index >= 6) {
            throw new Exception("The index of the flag specified was not valid!");
        }

        // Modify the flags field
        StringBuilder sb = new StringBuilder(getFlagsField());

        // Set the flag to the corresponding state value
        if (newState) {
            sb.setCharAt(index, STATE_TRUE);
        } else {
            sb.setCharAt(index, STATE_FALSE);
        }

        // Apply changes to the flags
        setFlagsField(sb.toString());
    }

    /**
     * Get the entire contents of the header in a string of binary. This method
     * combines all of the header fields into a single string of bits.
     * 
     * @return  the derived entire contents of the header in bits
     */
    public String getHeaderField() {
        return getSourcePortField() + getDestPortField() + getSequenceField()
                + getAckField() + getHeaderLengthField() + getReservedField()
                + getFlagsField() + getWindowField() + getChecksumField() + 
                getUrgentPointerField() + getOptionsField();
    }
    
    
    public String calculateChecksum() {
    
        // Perform the checksum on the pseudo-header + header + payload
        String data = getPseudoHeader().bits() + bits();
        
        long sumDecimal = 0;
        
        // Loop through ever 16 bits of the data
        for (int i = 0; i < data.length() / 16; i++) {
            
            // Sum all 16 bits of the data
            sumDecimal += binaryToDecimal(data.substring(i * 16, (i + 1) * 16));
        }
        
        // Wrap the sum if it is too long (65,535 in decimal = 16 bits of 1s in binary)
        while (sumDecimal > 65535) {
            
            // Wrap the sum
            sumDecimal -= 65535;
            sumDecimal++;
        }
        
        // Find the one's complement of the wrapped sum
        String complementBin = padRightToLength(decimalToBinary(~sumDecimal), 16);
        
        // One's complement is done on the sumDecimal in long number format,
        // so the binary number needed is preceded by many 1s. Take only the
        // last 16.
        complementBin = complementBin.substring(complementBin.length() - 16);
        
        
        // Return the one's complement in bits
        return complementBin;
    }

    
    public void generateNewChecksum() throws Exception {
        
        setChecksumField("0000000000000000");
        setChecksumField(calculateChecksum());
    }
    
    /**
     * Recomputes the header checksum then checks if the header has been corrupted.
     * If the header is corrupted, recalculating the checksum with the entire header
     * will yield one or more binary numbers that are not 0. Result must be 16 bits of
     * 0s to reasonably ensure that the segment header is not corrupted.
     * 
     * @return false if the header is corrupted
     */
    public boolean segmentHasValidChecksum() {
    
        return calculateChecksum().equals("0000000000000000");
    }
    
    // -------------------------------------------------------------------------
    //
    // Segment Statistics Calculation Methods
    //
    // -------------------------------------------------------------------------
    
    
    /**
     * Get the expected length of the header in decimal.
     * This method multiplies the header length field (32 bit octets) in decimal
     * form by 32.
     * 
     * @return  the number of bits that contain the header
     */
    public int getHeaderLengthInBits() {
        return binaryToDecimal(getHeaderLengthField()) * 32;
    }

    /**
     * Get the expected length of the options field in decimal.
     * This method finds the difference between the header length and previous
     * required header fields (always 160 bits or 5 * 32 bit words).
     * 
     * @return  the number of bits that contain the options
     */
    public final int getOptionsLengthInBits() {
        return getHeaderLengthInBits() - 160;
    }

    /**
     * Get the expected length of the payload field in decimal.
     * This method finds the difference between the total length and the header length.
     * 
     * @return  the number of bits that contain the payload
     */
    public final int getPayloadLengthInBits() {
        return getTotalLengthInBits() - getHeaderLengthInBits();
    }

    /**
     * Get the expected length of the segment in decimal.
     * This method multiplies the total length field (in octets) in decimal form by 8 (octet).
     * 
     * @return  the number of bits that contain the header and data
     */
    public final int getTotalLengthInBits() {
        return getPseudoHeader().getSegmentLengthInBits();
    }

    
    // -------------------------------------------------------------------------
    //
    // Segment Raw Data Output Methods
    //
    // -------------------------------------------------------------------------
    
    
    /**
     * The entire contents of the segment in binary.
     * @return  a continuous string of bits
     */
    public String bits() {
        return getHeaderField() + getPayloadField();
    }

    /**
     * The entire contents of the segment in hexadecimal.
     * @return  a continuous string of hex characters
     */
    public String hex() {
        return binaryToHex(bits());
    }

    
    // -------------------------------------------------------------------------
    //
    // Helper Data Type Converter Methods
    //
    // -------------------------------------------------------------------------
    
    
    /**
     * A helper method to convert strings of binary into strings of hexadecimal.
     * @param bin   the string of binary numbers
     * @return      the string of hex numbers
     */
    public static String binaryToHex(String bin) {

        String hex = "";

        // If the binary number is too short, pad it with zeros to the left to proper length
        bin = padLeftToLength(bin, 4);

        // Loop through every 4 bits and turn them into a hex character
        for (int i = 0; i < bin.length() / 4; i++) {

            hex += Long.toHexString(Long.parseLong(bin.substring(i * 4, (i + 1) * 4), 2));
        }

        // Convert characters to uppercase for neatness on output
        hex = hex.toUpperCase();

        return hex;

    }

    /**
     * A helper method to convert strings of hexadecimal into strings of binary.
     * @param hex   the string of hex numbers
     * @return      the string of binary numbers
     */
    public static String hexToBinary(String hex) {

        String bin = "";

        // Loop through each hex character and convert it to 4 bits
        for (int i = 0; i < hex.length(); i++) {

            // Find the bits of the hex value
            String padBin = "" + Long.toBinaryString(Long.parseLong(hex.substring(i, i + 1), 16));
            
            // Pad the binary number to 4 digits
            padBin = Segment.padLeftToLength(padBin, 4);

            bin += padBin;


        }

        return bin;
    }


    /**
     * Takes in a string of binary characters and converts them to an integer.
     * 
     * @param bin   the string of bits to convert
     * @return      the number in decimal of the given binary value
     */
    public static int binaryToDecimal(String bin) {
        int decimal = (int) Long.parseLong(bin, 2);
        return decimal;
    }

    /**
     * A helper method to convert a long integer into a string of binary numbers.
     * @param decimal   the decimal number
     * @return          the string of binary numbers
     */
    public static String decimalToBinary(long decimal) {
        return Long.toBinaryString(decimal);
    }

    /**
     * Takes in a string of hexadecimal characters and converts them to an integer.
     * 
     * @param hex   the string of hex chars to convert
     * @return      the number in decimal of the given hex value
     */
    public static int hexToDecimal(String hex) {
        int decimal = (int) Long.parseLong(hex, 16);
        return decimal;
    }

    /**
     * A helper method to convert a long integer into a string of hexadecimal.
     * @param decimal   the decimal number
     * @return          the string of hex numbers
     */
    public static String decimalToHex(long decimal) {
        return Long.toHexString(decimal).toUpperCase();
    }
    
    /**
     * Takes in a hexadecimal or binary input and outputs binary. This is used to
     * avoid multiple pattern matches to check if it is binary. If the input is
     * binary, the output will not be changed.
     * 
     * @param data                  the data in binary or hex
     * @return                      the data in binary
     * @throws Exception  the data could not be recognized as binary or hex
     */
    public static String toBinaryIfHex(String data) throws Exception {

        // Check if the data is in binary form
        if (data.matches("[01]+")) {
            
            return data;
        }
        
        // Check if the data is in hexadecimal form
        else if (data.matches("[0-9a-fA-F]+")) {

            // Convert the hex data to binary
            return hexToBinary(data);
        } else {
            
            throw new Exception("Could not convert data to binary (must be hex or binary): " + data);
        }
    }

    /**
     * Pad the string with zeros to the left up to a requested multiple of modulus. 
     * Can be used for binary and hexadecimal strings that need to fill a field
     * with a fixed length (modulus = length) or for dynamic fields that require
     * any size of a certain modulus.
     *
     * @param data  the data as a string to pad with 0s
     * @param mod   the modulus to pad to
     * @return      the data padded with 0s on the left
     */
    public static String padLeftToLength(String data, int mod) {

        while (data.length() % mod != 0) {

            data = "0" + data;
        }

        return data;
    }

    /**
     * Pad the string with zeros to the right up to a requested multiple of modulus. 
     * Can be used for binary and hexadecimal strings that need to fill a field
     * with a fixed length (modulus = length) or for dynamic fields that require
     * any size of a certain modulus.
     *
     * @param data  the data as a string to pad with 0s
     * @param mod   the modulus to pad to
     * @return      the data padded with 0s on the right
     */
    public static String padRightToLength(String data, int mod) {

        while (data.length() % mod != 0) {

            data += "0";
        }

        return data;
    }

    @Override
    public String toString() {
        return "Segment{" +
                "pseudoHeader=" + pseudoHeader.toString() +
                ", sourcePort='" + sourcePort + '\'' +
                ", destPort='" + destPort + '\'' +
                ", sequence='" + sequence + '\'' +
                ", ack='" + ack + '\'' +
                ", headerLength='" + headerLength + '\'' +
                ", reserved='" + reserved + '\'' +
                ", flags='" + flags + '\'' +
                ", window='" + window + '\'' +
                ", checksum='" + checksum + '\'' +
                ", urgentPointer='" + urgentPointer + '\'' +
                ", options='" + options + '\'' +
                ", payload='" + payload + '\'' +
                '}';
    }
}
