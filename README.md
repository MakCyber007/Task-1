# Task-1: Scan Your Local Network for Open Ports
Internship Tasks

  ## Overview
This repository documents the tasks completed during my internship, focusing on cybersecurity concepts.



### 1. Successfully Installed Nmap
I installed Nmap on my Windows laptop to conduct network analysis and security assessments.

### 2. Finding the Local IP Range of My Home Network
To determine my local network's IP range, I executed the following steps:

- Opened the command line and entered:

      ipconfig /all

  - Found the relevant network details:
    
        - IP Address: 192.168.1.6
        - Subnet Mask: 255.255.255.0
        - Default Gateway: 192.168.1.1
    
      Based on the subnet mask (255.255.255.0), the CIDR notation is /24, meaning the available IP addresses range from:
        192.168.1.1 - 192.168.1.255

  Refer to the following file: Finding_Local_IP_Range using cmd on Windows.png
    
### 3. Performing a TCP SYN Scan

  ### Running Nmap Scan
  To identify open ports on my local network, I executed the following command:
        
        nmap -sS 192.168.1.0/24
This scan revealed the following active hosts and open ports:

  1. 192.168.1.1 | local.airtelfiber.com | 53/tcp (DNS), 80/tcp (HTTP), 443/tcp (HTTPS), 5555/tcp (Freeciv) | 
  2. 192.168.1.2 | Unknown | No open ports detected | 
  3. 192.168.1.5 | Unknown | No open ports detected | 
  4. 192.168.1.6 | Local machine | 135/tcp (MSRPC), 139/tcp (NetBIOS-SSN), 445/tcp (Microsoft-DS) | 

Refer to the following files:
                              Nmap Scan(GUI) result screenshot.png,
                              Nmap Scan(cmd) result screenshot.png,
                              TCP-SYN Scan-html_file.html

### 4. Common Services Running on Open Ports
  - 53/tcp (DNS): Used for domain name resolution, allowing devices to translate domain names into IP addresses.
  - 80/tcp (HTTP): Standard web traffic port for unencrypted communication.
  - 443/tcp (HTTPS): Secure web traffic using SSL/TLS encryption.
  - 5555/tcp (Freeciv): Likely associated with the Freeciv game server.
  - 135/tcp (MSRPC): Microsoft Remote Procedure Call, used for inter-process communication.
  - 139/tcp (NetBIOS-SSN): NetBIOS session service, used for file and printer sharing in older Windows systems.
  - 445/tcp (Microsoft-DS): Server Message Block (SMB) protocol, used for file sharing in Windows environments.

### 5. Identifying Potential Security Risks
- HTTP (Port 80): Unencrypted web traffic is vulnerable to man-in-the-middle (MITM) attacks.
- Freeciv (Port 5555): If exposed to the internet, it could be exploited for unauthorized access.
- MSRPC (Port 135):  Microsoft Remote Procedure Call (RPC) service, poses significant security risks if left open and unrestricted. Attackers can exploit vulnerabilities in the RPC service on port 135 to execute code, gain unauthorized access to sensitive data, or launch denial-of-service attacks.  Often targeted in Windows-based exploits, including remote code execution and much more. ****HIGH RISK****
- NetBIOS-SSN (Port 139): Can be used for unauthorized file access or lateral movement in a network.****HIGH RISK****
- Microsoft-DS (Port 445):A common target for ransomware and SMB-based exploits like EternalBlue, WannaCry. ****HIGH RISK****

### 6. Capturing Nmap TCP SYN Scan with Wireshark
To analyze **Nmap TCP SYN scan** traffic, Wireshark was used to capture packets and filter only **SYN requests** without acknowledgments.

### **Process**
1. **Started Wireshark** and selected the WIFI network interface.
2. **Run the TCP SYN scan** using:
   '''cmd command:
   
           nmap -sS 192.168.1.0/24
   
- Filter the captured traffic in Wireshark using:
  
          tcp.flags.syn == 1 && tcp.flags.ack == 0
          - This isolates stealth SYN packets from the scan.
  
This capture provides proof of Nmap scan activity and supports further security assessments.

Refer to the following files:
                              nmap_tcp_syn_scan_capture.pcap,
                              Proof_of_Nmap_Scan.pcap 
 
### Conclusion
  This scan provided valuable insights into my local network’s security posture. I should consider further hardening measures, such as firewall rules and service restrictions, to mitigate risks.









            
            

          
