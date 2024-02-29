
# Network Incident Alarm 

## Project Overview

This project involves the development of a Python-based tool using Scapy to analyze network traffic for potential security incidents. The tool is capable of parsing both live network traffic and pre-captured PCAP files to detect various types of scans and clear-text credential transmissions.

## Implementation Details

### Correctly Implemented Features

- Detection of NULL, FIN, SMB, RDP and XMAS scans by analyzing TCP flags.
- Detection of Nikto web scanner attempts through HTTP User-Agent strings.
- Detection of VNC by looking at ports 5900-5903 and 5800-5803 for direct connections and web-based connections
- Detection of clear-text usernames and passwords transmitted via HTTP Basic Authentication, IMAP and FTP.
- Command-line interface for specifying network interface or PCAP file for analysis.
- The -r, , -i and -h flags for reading files, sniffing packets and the help option for the User works
- the -i flag for interface hasn't worke

### What hasn't been implemented 



### Collaborations

- Discussions regarding packet analysis techniques were held with classmates on Discord section Lab4, though specific implementation details were independently developed.
- Utilized Scapy documentation and online forums for troubleshooting common packet parsing issues.
- Looking up Wireshark documentation for ports where certain scans and incidents should be in.
- Looking up Regular Expressions for searching and credentials for usernames and passwords 
- Looking up base64 to decode https basic authentication credentials 

### Time Investment

- Approximately 40 hours were spent on completing this assignment, including development, testing with various PCAP files, and documentation.

### Dependencies

- Scapy: Used for packet manipulation and analysis.
- Python 3: Development language.

## Reflections

### Heuristic Effectiveness

The heuristics used for incident detection, while effective in identifying certain patterns, have limitations. 
For instance, the reliance on specific flag combinations for scan detection or simple string matching for
 credential detection could lead to both false positives and false negatives. The effectiveness of these 
 heuristics is highly dependent on the network context and the sophistication of potential attackers.

### Future Enhancements

- **Packet Reassembly:** Implementing TCP stream reassembly would enhance the detection of incidents that span 
   multiple packets.
- **Encryption Detection:** Adding functionality to detect the use of encrypted channels for transmitting 
  sensitive information could be beneficial, though challenging due to encryption's nature.


