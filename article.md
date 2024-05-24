# Common Security Risks in Network Infrastructure

In the modern interconnected landscape, an organization's IT operations heavily rely on its network infrastructure. Mitigating associated risks is paramount for security and operational integrity. Here, we explore common security risks in network infrastructure, providing descriptions, potential impacts, and real-world examples. For simulating and understanding computer networks, including their configuration and socket programming, widely used tools include CISCO Packet Tracer and OMNETPP.

### Understanding the OSI Model: A Basic Overview

The OSI model is a conceptual framework for network communications, comprising seven layers with specific functions and protocols. It aids in standardizing networking protocols, promoting interoperability between different systems and software, regardless of their internal structures and technologies.
![Pasted image 20240524122957](https://github.com/NucleiAv/codecademy/assets/105632119/0fb80a6d-f552-4812-b658-71a15ac48f81)

![Pasted image 20240524124658](https://github.com/NucleiAv/codecademy/assets/105632119/00b9c9d8-82a4-4c05-b6d8-41bd95395128)


**Assessment 1: Q. Which is the transmits data using TCP and/or UDP?**

**Assessment 2: Q. Which is the first and last layer in OSI Model?**

## Common Security Risks & Attacks
### 1. Unsecured Network Devices

Network devices like routers, switches, and firewalls are crucial components of any network, but if left unsecured, they become prime targets for cyber attackers. Unauthorized access to these devices can result in network downtime, data breaches, and traffic hijacking, enabling further malicious activities. For instance, in a hypothetical scenario, a malicious actor exploits a router with default settings and password, redirecting all traffic through a malicious server to intercept and manipulate sensitive data.

#### Pseudo Code for Identifying and Securing Unsecured Network Devices

```
// Pseudo Code to Identify and Secure Unsecured Network Devices

// Initialize tools
networkScanner = InitializeNetworkScanner()
configManagementTool = InitializeConfigManagementTool()

// Define network range to scan
networkRange = "192.168.0.0/24"

// Function to identify unsecured devices
function identifyUnsecuredDevices(networkRange):
    // Scan the network range for devices
    devices = networkScanner.scan(networkRange)
    unsecuredDevices = []

    // Loop through each detected device
    for device in devices:
        // Retrieve device configuration
        config = configManagementTool.getConfig(device)

        // Check for default settings
        if config.username == "admin" and config.password == "admin":
            unsecuredDevices.append(device)
        elif not config.firmwareUpToDate:
            unsecuredDevices.append(device)
        elif not config.encryptionEnabled:
            unsecuredDevices.append(device)

    return unsecuredDevices

// Function to secure a device
function secureDevice(device):
    // Change default credentials
    configManagementTool.changeCredentials(device, newUsername, newPassword)

    // Update firmware
    if not configManagementTool.isFirmwareUpToDate(device):
        configManagementTool.updateFirmware(device)

    // Enable encryption
    if not configManagementTool.isEncryptionEnabled(device):
        configManagementTool.enableEncryption(device)

    // Log the securing actions
    log("Secured device: " + device.ipAddress)

// Main process
function main():
    // Identify unsecured devices
    unsecuredDevices = identifyUnsecuredDevices(networkRange)

    // Secure each unsecured device
    for device in unsecuredDevices:
        secureDevice(device)

    // Summary
    log("Total unsecured devices identified and secured: " + unsecuredDevices.length)

// Execute the main process
main()
```

#### Explanation:
- Tools are initialized for network scanning and configuration management.
- A network range, `192.168.0.0/24`, is specified for scanning IP addresses.
- The process identifies unsecured devices by scanning the network and checking their configurations.
- Devices are deemed unsecured if they use default credentials, have outdated firmware, or lack encryption.
- Each unsecured device is secured by changing default credentials, updating firmware, and enabling encryption.
- Actions taken to secure devices are logged.
- The main process executes, identifying and securing unsecured devices while logging the results.

**Assessment 3: Q. What are the default credentials of network device?**

**Assessment 4: Q. What are the parameters for a device to be deemed insecure?**

### 3. Vulnerable Network Services and Protocols

Many network services and protocols, such as Telnet, FTP, and outdated versions of SNMP, are inherently vulnerable and can expose networks to attacks like eavesdropping and unauthorized access. Exploiting these vulnerabilities can allow attackers to capture sensitive information, gain unauthorized access, or disrupt network services, leading to significant operational and reputational damage. For instance, an organization using Telnet for remote network management might find that an attacker intercepts Telnet sessions, captures login credentials, and gains control of critical network infrastructure, thereby disrupting business operations.

**Assessment 5: Q. Find the fullforms and functions of TelNet, FTP and SNMP?**

### 4. Poor Patch Management

Regularly updating and patching network devices and software is essential to address security vulnerabilities effectively. Failure to do so can leave networks vulnerable to known exploits, making them easy targets for attackers. Exploiting these vulnerabilities can result in data breaches, malware infections, and the loss of sensitive information. For instance, the Equifax data breach in 2017, affecting 147 million individuals, was attributed to the exploitation of a known vulnerability in the Apache Struts web application framework. Despite a patch being available, it was not applied promptly, highlighting the critical importance of keeping systems up-to-date.

**Assessment 6: Q. What can Poor Patch Management lead to?**

### 5. Insecure Remote Access

The need for secure remote access to networks has surged with the rise of remote work. Insecure methods like poorly configured VPNs or RDP without MFA pose significant risks, allowing attackers unauthorized access. This can lead to further attacks from within the network, potentially compromising sensitive data and critical systems. For instance, during the COVID-19 pandemic, an organization's use of RDP without MFA led to a ransomware attack, encrypting sensitive data and demanding ransom for its release.

### 6. Unauthorized Access

Unauthorized access to network resources poses significant risks, often facilitated by weak passwords, unpatched vulnerabilities, or social engineering. The potential impact ranges from data breaches to complete system compromise, serving as a foothold for further attacks. For instance, an attacker exploiting a weak password on a company's VPN can navigate the internal network, accessing confidential data and potentially deploying ransomware.

**Assessment 7: Q. A advisory remotely accesses a network. This comes under - Insecure Remote Access / Unauthorized Access / Both ?**

### 7. Distributed Denial of Service (DDoS) Attacks

DDoS attacks flood networks with internet traffic, rendering services unavailable to legitimate users. This can lead to significant downtime, lost revenue, and damage to reputation. In 2016, the Dyn DNS provider experienced a massive DDoS attack, disrupting major websites like Twitter and Netflix. This incident, caused by the Mirai botnet, showcased the destructive potential of DDoS attacks on network infrastructure.

![Pasted image 20240524130457](https://github.com/NucleiAv/codecademy/assets/105632119/3db35bf3-c76c-406c-bf4d-0a0b6e16f207)

#### Pseudo Code for DDoS
```
function DDoS_Attack(target_IP, num_attackers):
    for attacker in range(num_attackers):
        start_attack_thread(target_IP)

function start_attack_thread(target_IP):
    while True:
        send_request(target_IP)

function send_request(target_IP):
    // Craft a request packet (e.g., SYN flood for TCP)
    packet = craft_packet()
    
    // Send the packet to the target IP address
    send_packet(packet, target_IP)

function craft_packet():
    // Create a malicious packet with spoofed source IP addresses
    // to make it difficult to trace back to the real attackers
    // (e.g., SYN packet with random source IP and port)

function send_packet(packet, target_IP):
    // Send the packet to the target IP address using raw sockets
    // (e.g., using Python's socket library)
```
#### Explanation
- **DDoS_Attack:**
  - Initiates attack by spawning multiple threads.
  - Each thread sends requests to target IP.

- **start_attack_thread:**
  - Represents individual attacker thread.
  - Continuously sends requests to target IP.

- **send_request:**
  - Crafts and sends malicious request packet.
  - May contain spoofed source IP addresses.

- **craft_packet:**
  - Generates malicious packet (e.g., SYN flood).
  - Aims to overwhelm target's resources.

- **send_packet:**
  - Sends crafted packet using raw sockets.
  - Allows manipulation of network packets directly.

### 8. Man-in-the-Middle (MitM) Attacks

MitM attacks involve intercepting and altering communication between two parties without their knowledge. This can lead to the theft of sensitive information and the injection of malicious content. For example, an attacker sets up a rogue Wi-Fi hotspot, intercepting and modifying communications from unsuspecting users to capture sensitive data.

![Pasted image 20240524130534](https://github.com/NucleiAv/codecademy/assets/105632119/96772298-eb4e-4d58-9956-7f446057e407)

#### Pseudo Code/Steps for MitM
```
1. Begin MITM Attack

2. Initialize:
    - Attacker's Machine (A)
    - Victim's Machine (V)
    - Legitimate Server (S)

3. ARP Spoofing:
    - A sends ARP packets to V and S, claiming to be the other party
    - V and S update their ARP tables, associating A's MAC address with the IP address of the other party

4. Intercept Traffic:
    - A intercepts communication between V and S
    - A captures packets passing between V and S

5. Relay Packets:
    - A forwards packets from V to S and vice versa, acting as a "middleman" in the communication

6. Eavesdrop or Modify:
    - A can eavesdrop on the communication between V and S to steal sensitive information
    - A can modify the content of packets before relaying them, potentially injecting malicious code or altering data

7. End MITM Attack
```


**Assessment 8: Q. Define DDoS and MitM.**

### 9. Insider Threats

Insider threats stem from individuals within an organization misusing their access to harm the network, whether intentionally or unintentionally. These threats, often leveraging trusted access, can lead to severe consequences like data breaches and financial loss. For example, a disgruntled employee with administrative privileges might intentionally delete critical files, while another employee might inadvertently share confidential information, both scenarios resulting in significant damage to the organization.

**Assessment 9: Q. What is the main cause of insider threats?**

### Conclusion

Understanding and mitigating network infrastructure risks is crucial for strong cybersecurity. Securing devices, implementing segmentation, using secure protocols, patch management, and ensuring secure remote access are key. Regular audits and staying updated on security trends are vital in the evolving network security landscape.
For more dive-diving into Wifi Hacking, I have written a complete handbook for the same at Medium.

**Assessment 10: Rate the article and Provide Feedback.**
