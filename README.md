# VMware vCenter & Linux VM Monitoring Microsoft Teams Bot

This project is a Microsoft Teams chatbot for VMware vCenter and Linux VMs. It helps sysadmins quickly search, monitor, and analyze virtual machines—right from Teams—combining vCenter event queries, live Linux SSH monitoring, and AI-driven health checks.

---

## Features

- **Microsoft Teams Integration**  
  - Interact via Teams chat commands  
  - OAuth2 authentication (Graph API) for secure messaging

- **VMware vCenter Operations**  
  - Search VMs by name or keyword  
  - Get detailed VM hardware & status info  
  - Query and display recent VM events  
  - Batch event search for multiple VMs

- **Linux VM SSH Monitoring**  
  - Connect to VMs via SSH (password/private key)  
  - Gather system metrics: CPU, RAM, storage, network, processes, services, security logs  
  - Output comprehensive system health reports

- **AI-Driven VM Analysis**  
  - Connects to Google Gemini API  
  - AI provides concise health status, risks, and recommendations for any VM
