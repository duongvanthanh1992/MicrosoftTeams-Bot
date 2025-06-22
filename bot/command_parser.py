# bot/command_parser.py

import os
from ai.gemini_client import GeminiClient
from vcenter.vcenter_task import get_vm_events_by_name
from vcenter.vcenter_task import get_vm_info_by_keyword
from vcenter.vcenter_task import get_vm_events_by_keyword


class CommandParser:
    def __init__(self):
        # Get credentials from environment
        self.vc_host = os.environ.get("VC_HOST")
        self.vc_user = os.environ.get("VC_USERNAME")
        self.vc_pass = os.environ.get("VC_PASSWORD")
        
        # Initialize AI client
        self.gemini_client = GeminiClient()

    def process_command(self, content):
        """Process command and return response"""
        content = content.lower().strip()
        
        # Handle supported commands
        if content == "/bot":
            return "🤖 Bot is up and running!"

        elif content == "/clear":
            return "Waiting for Hendry to approve API permissions for message deletion."

        elif content.startswith("/find"):
            return self._handle_find_command(content)

        elif content.startswith("/events"):
            return self._handle_events_command(content)

        elif content.startswith("/auto-events"):
            return self._handle_auto_events_command(content)

        elif content.startswith("/ai-check-vcenter"):
            return self._handle_ai_check_vcenter_command(content)

        elif content.startswith("/ai-check-ssh"):
            return self._handle_ai_check_ssh_command(content)
        
        elif content.startswith("/ai-check-security"):
            return self._handle_ai_check_security_command(content)
        
        elif content == "/help":
            return self._get_help_message()

        return None

    def _handle_find_command(self, content):
        """Handle /find command"""
        vm_name = content[5:].strip()
        if not vm_name:
            return "❌ Please provide a VM name. Usage: /find &lt;VM Name&gt;"
            
        print(f"🔍 Searching for VM: {vm_name}")
        return get_vm_info_by_keyword(
            keyword=vm_name,
            host=self.vc_host,
            user=self.vc_user,
            password=self.vc_pass
        )

    def _handle_events_command(self, content):
        """Handle /events command"""
        parts = content[7:].strip().split()
        if not parts:
            return "❌ Please provide a VM name. Usage: /events &lt;VM Name&gt; [days]"
        
        vm_name = parts[0]
        days = 7  # default
        
        if len(parts) > 1:
            try:
                days = int(parts[1])
                if days < 1 or days > 30:
                    return "❌ Days must be between 1 and 30."
            except ValueError:
                return "❌ Invalid number of days. Usage: /events &lt;VM Name&gt; [days]"
        
        print(f"📋 Getting events for VM: {vm_name} (last {days} days)")
        return get_vm_events_by_name(
            vm_name=vm_name,
            host=self.vc_host,
            user=self.vc_user,
            password=self.vc_pass,
            days=days
        )

    def _handle_auto_events_command(self, content):
        """Handle /auto-events command"""
        parts = content[12:].strip().split()
        if not parts:
            return "❌ Please provide a keyword. Usage: /auto-events &lt;keyword&gt; [days]"
        
        keyword = parts[0]
        days = 7  # default
        
        if len(parts) > 1:
            try:
                days = int(parts[1])
                if days < 1 or days > 30:
                    return "❌ Days must be between 1 and 30."
            except ValueError:
                return "❌ Invalid number of days. Usage: /auto-events &lt;keyword&gt; [days]"
        
        print(f"📋 Searching VM events with keyword: {keyword} (last {days} days)")
        return get_vm_events_by_keyword(
            keyword=keyword,
            host=self.vc_host,
            user=self.vc_user,
            password=self.vc_pass,
            days=days
        )

    def _handle_ai_check_vcenter_command(self, content):
        """Handle /ai-check-vcenter command"""
        vm_name = content[17:].strip()
        if not vm_name:
            return "❌ Please provide a VM name. Usage: /ai-check-vcenter &lt;VM Name&gt;"
        
        print(f"🤖 Running AI vCenter analysis for VM: {vm_name}")
        # Removed host, user, password parameters - now handled by GeminiClient internally
        return self.gemini_client.analyze_vcenter_data(vm_name)

    def _handle_ai_check_ssh_command(self, content):
        """Handle /ai-check-ssh command"""
        vm_name = content[13:].strip()
        if not vm_name:
            return "❌ Please provide a VM name. Usage: /ai-check-ssh &lt;VM Name&gt;"
        
        print(f"🔗 Running SSH analysis for VM: {vm_name}")
        return self.gemini_client.analyze_ssh_data(vm_name)

    def _handle_ai_check_security_command(self, content):
        """Handle /ai-check-security command"""
        vm_name = content[18:].strip()
        if not vm_name:
            return "❌ Please provide a VM name. Usage: /ai-check-security &lt;VM Name&gt;"
        
        print(f"🛡️ Running security analysis for VM: {vm_name}")
        return self.gemini_client.analyze_security_data(vm_name)

    def _get_help_message(self):
        """Return help message"""
        return (
            "<div style='margin-top:10px;'>"
            "<b>🤖 Available commands:</b><br><br>"
            "<b>/bot</b> - Check if bot is alive.<br>"
            "<b>/find &lt;VM Name&gt;</b> - Approximate VM name search.<br>"
            "<b>/events &lt;VM Name&gt; [days]</b> - Get VM events (default: 7 days).<br>"
            "<b>/auto-events &lt;keyword&gt; [days]</b> - Search VMs and get their events.<br>"
            "<b>/clear</b> - Waiting for Hendry to approve API permissions for message deletion.<br>"
            "<br><i>Examples:</i><br>"
            "<b>/events BINH-TestVM-04 10</b> - Get events for BINH-TestVM-04 in last 10 days<br>"
            "<b>/auto-events thanh</b> - Search VMs containing 'thanh' (7 days default) of events<br>"
            "<br><i>AI Analysis Commands:</i><br>"
            "<b>/ai-check-vcenter VAULT-13.149</b> - Get AI analysis of VM VAULT-13.149 (14 days default) from vCenter<br>"
            "<b>/ai-check-ssh ELK-13.144</b> - Get AI analysis of VM VAULT-13.149 from SSH<br>"
            "<b>/ai-check-security ELK-13.145</b> - Security analysis of VAULT-13.149<br>"
            "</div>"
        )