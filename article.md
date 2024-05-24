# Common Security Risks in Network Infrastructure

In the modern interconnected landscape, an organization's IT operations heavily rely on its network infrastructure. Mitigating associated risks is paramount for security and operational integrity. Here, we explore common security risks in network infrastructure, providing descriptions, potential impacts, and real-world examples. For simulating and understanding computer networks, including their configuration and socket programming, widely used tools include CISCO Packet Tracer and OMNETPP.

### Understanding the OSI Model: A Basic Overview

The OSI model is a conceptual framework for network communications, comprising seven layers with specific functions and protocols. It aids in standardizing networking protocols, promoting interoperability between different systems and software, regardless of their internal structures and technologies.
![[Pasted image 20240524124658.png]]

![[Pasted image 20240524122957.png]]

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

### 3. Vulnerable Network Services and Protocols

Many network services and protocols, such as Telnet, FTP, and outdated versions of SNMP, are inherently vulnerable and can expose networks to attacks like eavesdropping and unauthorized access. Exploiting these vulnerabilities can allow attackers to capture sensitive information, gain unauthorized access, or disrupt network services, leading to significant operational and reputational damage. For instance, an organization using Telnet for remote network management might find that an attacker intercepts Telnet sessions, captures login credentials, and gains control of critical network infrastructure, thereby disrupting business operations.

### 4. Poor Patch Management

Regularly updating and patching network devices and software is essential to address security vulnerabilities effectively. Failure to do so can leave networks vulnerable to known exploits, making them easy targets for attackers. Exploiting these vulnerabilities can result in data breaches, malware infections, and the loss of sensitive information. For instance, the Equifax data breach in 2017, affecting 147 million individuals, was attributed to the exploitation of a known vulnerability in the Apache Struts web application framework. Despite a patch being available, it was not applied promptly, highlighting the critical importance of keeping systems up-to-date.

### 5. Insecure Remote Access

The need for secure remote access to networks has surged with the rise of remote work. Insecure methods like poorly configured VPNs or RDP without MFA pose significant risks, allowing attackers unauthorized access. This can lead to further attacks from within the network, potentially compromising sensitive data and critical systems. For instance, during the COVID-19 pandemic, an organization's use of RDP without MFA led to a ransomware attack, encrypting sensitive data and demanding ransom for its release.

### 6. Unauthorized Access

Unauthorized access to network resources poses significant risks, often facilitated by weak passwords, unpatched vulnerabilities, or social engineering. The potential impact ranges from data breaches to complete system compromise, serving as a foothold for further attacks. For instance, an attacker exploiting a weak password on a company's VPN can navigate the internal network, accessing confidential data and potentially deploying ransomware.

### 7. Distributed Denial of Service (DDoS) Attacks

DDoS attacks flood networks with internet traffic, rendering services unavailable to legitimate users. This can lead to significant downtime, lost revenue, and damage to reputation. In 2016, the Dyn DNS provider experienced a massive DDoS attack, disrupting major websites like Twitter and Netflix. This incident, caused by the Mirai botnet, showcased the destructive potential of DDoS attacks on network infrastructure.

![[Pasted image 20240524130457.png]]

### 8. Man-in-the-Middle (MitM) Attacks

MitM attacks involve intercepting and altering communication between two parties without their knowledge. This can lead to the theft of sensitive information and the injection of malicious content. For example, an attacker sets up a rogue Wi-Fi hotspot, intercepting and modifying communications from unsuspecting users to capture sensitive data.

![[Pasted image 20240524130534.png]]

### 9. Insider Threats

Insider threats stem from individuals within an organization misusing their access to harm the network, whether intentionally or unintentionally. These threats, often leveraging trusted access, can lead to severe consequences like data breaches and financial loss. For example, a disgruntled employee with administrative privileges might intentionally delete critical files, while another employee might inadvertently share confidential information, both scenarios resulting in significant damage to the organization.
### Conclusion

Understanding and mitigating network infrastructure risks is crucial for strong cybersecurity. Securing devices, implementing segmentation, using secure protocols, patch management, and ensuring secure remote access are key. Regular audits and staying updated on security trends are vital in the evolving network security landscape.
For more dive-diving into Wifi Hacking, I have written a complete handbook for the same at Medium.