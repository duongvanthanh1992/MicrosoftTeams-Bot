# ai/gemini_client.py

import os
import re
import requests
from monitor.ssh_monitor import get_vm_ssh_analysis
from vcenter.vcenter_task import get_vm_events_by_name
from vcenter.vcenter_task import get_vm_info_by_keyword


class GeminiClient:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
        
        # vCenter credentials from environment variables
        self.vcenter_host = os.environ.get("VC_HOST")
        self.vcenter_user = os.environ.get("VC_USERNAME")
        self.vcenter_password = os.environ.get("VC_PASSWORD")
        
    def _check_api_key(self):
        """Check if API key is available"""
        if not self.api_key:
            return "❌ Gemini API key not configured. Please set GEMINI_API_KEY environment variable."
        return None

    def _check_vcenter_credentials(self):
        """Check if vCenter credentials are available"""
        missing_creds = []
        if not self.vcenter_host:
            missing_creds.append("VC_HOST")
        if not self.vcenter_user:
            missing_creds.append("VC_USERNAME")
        if not self.vcenter_password:
            missing_creds.append("VC_PASSWORD")
            
        if missing_creds:
            return f"❌ vCenter credentials not configured. Please set environment variables: {', '.join(missing_creds)}"
        return None

    def _call_gemini_api(self, prompt, temperature=0.2, max_tokens=1500):
        """Make API call to Gemini"""
        try:
            url = f"{self.base_url}?key={self.api_key}"
            
            headers = {
                "Content-Type": "application/json"
            }
            
            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": temperature,
                    "topK": 32,
                    "topP": 0.9,
                    "maxOutputTokens": max_tokens,
                    "candidateCount": 1
                },
                "safetySettings": [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH", 
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    }
                ]
            }
            
            print("🤖 Sending data to Gemini AI for analysis...")
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                
                # Extract the generated text
                if 'candidates' in result and len(result['candidates']) > 0:
                    ai_response = result['candidates'][0]['content']['parts'][0]['text']
                    return ai_response
                else:
                    return "❌ AI analysis failed: No response generated"
            else:
                return f"❌ AI analysis failed: HTTP {response.status_code} - {response.text}"
                
        except requests.exceptions.RequestException as e:
            return f"❌ AI analysis failed: Network error - {str(e)}"
        except Exception as e:
            return f"❌ AI analysis failed: {str(e)}"

    def _markdown_to_html(self, text, title):
        """Convert Markdown formatting to HTML for Teams"""
        # Convert **bold** to <b>bold</b>
        text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
        # Convert *italic* to <i>italic</i>
        text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
        # Convert line breaks
        text = text.replace('\n', '<br>')
        # Convert bullet points - fix the regex to handle multiple list items
        text = re.sub(r'^\s*[-*+]\s+(.+)', r'<li>\1</li>', text, flags=re.MULTILINE)
        text = re.sub(r'(<li>.*?</li>)', r'<ul>\1</ul>', text, flags=re.DOTALL)
        
        formatted_response = (
            f"<div style='margin-top:10px;'>"
            f"<b>🤖 {title}</b><br><br>"
            f"{text.replace(chr(10), '<br>')}"
            f"</div>"
        )
        return formatted_response

    def _get_vcenter_analysis_prompt(self, vm_info, vm_events):
        """Generate prompt for vCenter data analysis"""
        # Strip HTML tags for cleaner AI input
        clean_vm_info = re.sub(r'<.*?>', '', vm_info)
        clean_vm_events = re.sub(r'<.*?>', '', vm_events)
        
        prompt = f"""
You are an infrastructure analyst. Analyze the following VMware virtual machine based on vCenter data (no access inside the VM). Your analysis should cover configuration, recent events, resource allocation, and health. Highlight any issues or unusual events from the last 7-14 days. 

## VM INFORMATION:
{clean_vm_info}

## RECENT EVENTS (last 14 days):
{clean_vm_events}

## 1. Health Status
Overall status (HEALTHY/WARNING/CRITICAL) with reason.

## 2. Notable Events & Participants
Highlight anything important or abnormal.

## 3. Recommendations
Suggest improvements, troubleshooting or follow-up actions (do not include anything requiring in-guest access).

## 4. Summary
Short technical summary (2-3 lines). Focus only on what vCenter can see.
"""
        return prompt

    def _get_ssh_analysis_prompt(self, ssh_data):
        """Generate prompt for SSH monitoring data analysis"""
        # Strip HTML tags for cleaner AI input
        clean_ssh_data = re.sub(r'<.*?>', '', ssh_data)
        
        prompt = f"""
You are a Linux Engineer. Given the following SSH monitoring report, provide a structured overview to help identify the root cause of VM incidents quickly. Focus on the following aspects:

- **System Info:** OS, uptime, kernel, hardware specs
- **Resource Usage:** CPU, RAM, Disk usage, top processes
- **Disk & Filesystem:** Storage status, directories consuming large space
- **Network:** Active interfaces, listening ports, recent connections
- **Service Status:** Any failed or stopped services
- **Security:** Recent login activities, sudo usage, suspicious entries in auth logs

Summarize each section, highlight any values or events that are abnormal, and suggest what might require further investigation. If you detect possible security issues, mark them clearly.

End your report with a concise summary and an incident triage priority (HIGH/MEDIUM/LOW).

Here is the report:
{clean_ssh_data}
"""
        return prompt

    def _get_security_analysis_prompt(self, ssh_data):
        """Generate prompt for security-focused SSH analysis"""
        # Strip HTML tags for cleaner AI input
        clean_ssh_data = re.sub(r'<.*?>', '', ssh_data)
        
        prompt = f"""
You are a security analyst. Focus only on the security-related information from this SSH monitoring report. Analyze:

- Recent failed/successful logins
- Sudo activity
- Suspicious users or processes
- Unusual network connections or open ports
- Any abnormal or error messages from the auth logs

Highlight anything that suggests compromise or misconfiguration. Give clear recommendations for incident response.

Here is the report:
{clean_ssh_data}
"""
        return prompt

    def analyze_vcenter_data(self, vm_name, temperature=0.2):
        """Analyze vCenter VM data using Gemini AI"""
        # Check API key
        api_error = self._check_api_key()
        if api_error:
            return api_error
            
        # Check vCenter credentials
        vcenter_error = self._check_vcenter_credentials()
        if vcenter_error:
            return vcenter_error
            
        try:
            # Get vCenter data with proper credentials
            print(f"📊 Gathering vCenter data for VM: {vm_name}")
            vm_info = get_vm_info_by_keyword(vm_name, self.vcenter_host, self.vcenter_user, self.vcenter_password)
            vm_events = get_vm_events_by_name(vm_name, self.vcenter_host, self.vcenter_user, self.vcenter_password, days=14)
            
            # Check if VM was found
            if "No VM found" in vm_info or "not found" in vm_info:
                return f"❌ VM '{vm_name}' not found in vCenter"
            
            # Generate prompt
            prompt = self._get_vcenter_analysis_prompt(vm_info, vm_events)
            
            # Get AI analysis
            ai_response = self._call_gemini_api(prompt, temperature)
            
            # Format response
            return self._markdown_to_html(ai_response, f"vCenter Analysis for {vm_name}")
            
        except Exception as e:
            return f"❌ Error analyzing vCenter data: {str(e)}"

    def analyze_ssh_data(self, vm_name, temperature=0.2):
        """Analyze SSH monitoring data using Gemini AI (Linux Engineer perspective)"""
        # Check API key
        api_error = self._check_api_key()
        if api_error:
            return api_error
            
        try:
            # Get SSH data
            print(f"🔐 Gathering SSH monitoring data for VM: {vm_name}")
            ssh_data = get_vm_ssh_analysis(vm_name)
            
            # Generate prompt
            prompt = self._get_ssh_analysis_prompt(ssh_data)
            
            # Get AI analysis
            ai_response = self._call_gemini_api(prompt, temperature)
            
            # Format response
            return self._markdown_to_html(ai_response, f"Linux Engineer Analysis for {vm_name}")
            
        except Exception as e:
            return f"❌ Error analyzing SSH data: {str(e)}"

    def analyze_security_data(self, vm_name, temperature=0.2):
        """Analyze SSH data from security analyst perspective"""
        # Check API key
        api_error = self._check_api_key()
        if api_error:
            return api_error
            
        try:
            # Get SSH data
            print(f"🛡️ Gathering security data for VM: {vm_name}")
            ssh_data = get_vm_ssh_analysis(vm_name)
            
            # Generate security-focused prompt
            prompt = self._get_security_analysis_prompt(ssh_data)
            
            # Get AI analysis
            ai_response = self._call_gemini_api(prompt, temperature)
            
            # Format response
            return self._markdown_to_html(ai_response, f"Security Analysis for {vm_name}")
            
        except Exception as e:
            return f"❌ Error analyzing security data: {str(e)}"