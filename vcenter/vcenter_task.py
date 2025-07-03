# vcenter_task.py

import ssl
from pyVmomi import vim
from datetime import datetime, timedelta
from pyVim.connect import SmartConnect, Disconnect


# Manage and reuse vCenter connection
class VCenterClient:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.service_instance = None

    def connect(self):
        if not self.service_instance:
            ssl_context = ssl._create_unverified_context()
            self.service_instance = SmartConnect(
                host=self.host,
                user=self.user,
                pwd=self.password,
                sslContext=ssl_context
            )

    def disconnect(self):
        if self.service_instance:
            Disconnect(self.service_instance)
            self.service_instance = None

    def get_instance(self):
        self.connect()
        return self.service_instance


# VMware operations
class VMwareTask:
    @staticmethod
    def vcenter_list_all_vm(service_instance):
        content = service_instance.RetrieveContent()
        container_view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        vms = [vm.name for vm in container_view.view]
        container_view.Destroy()
        return vms

    @staticmethod
    def get_vm_info(service_instance, vm_name):
        content = service_instance.RetrieveContent()
        container_view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )

        for vm in container_view.view:
            if vm_name.lower() == vm.name.lower():
                summary = vm.summary
                runtime = summary.runtime
                config = summary.config

                status = {
                    'name': vm.name,
                    'power_state': runtime.powerState,
                    'ram_size_gb': config.memorySizeMB / 1024,
                    'cpu_cores': config.numCpu,
                    'ip_address': vm.guest.ipAddress,
                    'host_name': vm.runtime.host.name if vm.runtime.host else "N/A",
                    'dns_name': vm.guest.hostName or "N/A or VMware Tools is not installed.",
                    'disks': []
                }

                for device in vm.config.hardware.device:
                    if isinstance(device, vim.vm.device.VirtualDisk):
                        disk_size_gb = device.capacityInBytes / (1024 ** 3)
                        status['disks'].append({
                            'name': device.deviceInfo.label,
                            'size_gb': round(disk_size_gb, 2)
                        })

                container_view.Destroy()
                return status

        container_view.Destroy()
        return None

    @staticmethod
    def get_vm_events(service_instance, vm_name, days=7, limit=20):
        """Get latest events for a specific VM within the specified number of days"""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            vm_obj = None
            for vm in container_view.view:
                if vm.name.lower() == vm_name.lower():
                    vm_obj = vm
                    break

            container_view.Destroy()

            if not vm_obj:
                return None

            # Get events from event manager
            event_manager = content.eventManager
            now = datetime.utcnow()
            time_from = now - timedelta(days=days)

            # Create event filter specification
            filter_spec = vim.event.EventFilterSpec(
                entity=vim.event.EventFilterSpec.ByEntity(
                    entity=vm_obj, 
                    recursion='self'
                ),
                time=vim.event.EventFilterSpec.ByTime(
                    beginTime=time_from,
                    endTime=now
                ),
                # Request more events than needed to ensure we get enough after sorting
                maxCount=limit * 2  # Get more events to sort from
            )

            # Query events
            events = event_manager.QueryEvents(filter_spec)
            
            if not events:
                return []

            # Sort events by creation time (newest first)
            sorted_events = sorted(events, key=lambda x: x.createdTime, reverse=True)
            
            # Take only the requested number of events
            latest_events = sorted_events[:limit]

            # Format events
            formatted_events = []
            for event in latest_events:
                try:
                    timestamp = event.createdTime.strftime("%Y-%m-%d %H:%M:%S UTC")
                    user_info = f" (by {event.userName})" if hasattr(event, 'userName') and event.userName else ""
                    event_type = event.__class__.__name__
                    
                    # Get the message - try fullFormattedMessage first, then fallback
                    if hasattr(event, 'fullFormattedMessage') and event.fullFormattedMessage:
                        message = event.fullFormattedMessage
                    elif hasattr(event, 'description') and event.description:
                        message = event.description
                    else:
                        message = f"Event: {event_type}"
                    
                    formatted_events.append({
                        'timestamp': timestamp,
                        'event_type': event_type,
                        'message': message,
                        'user': user_info,
                        'full_event': f"[{timestamp}] {message}{user_info}"
                    })
                except Exception as e:
                    # Skip problematic events but continue processing
                    print(f"Warning: Could not format event: {e}")
                    continue

            return formatted_events

        except Exception as e:
            print(f"Error retrieving VM events: {e}")
            return None


def get_vm_info_by_keyword(keyword: str, host: str, user: str, password: str) -> str:
    """Search for VMs by keyword and return their information"""
    if len(keyword) < 4:
        return "🔒 Keyword must be at least 4 characters to avoid excessive matches."

    vc_client = VCenterClient(host, user, password)
    try:
        service_instance = vc_client.get_instance()
        all_vms = VMwareTask.vcenter_list_all_vm(service_instance)
        matched_vms = [name for name in all_vms if keyword.lower() in name.lower()]

        if not matched_vms:
            return f"No VM found matching the keyword: <b>{keyword}</b>"

        results = []
        for vm_name in matched_vms:
            info = VMwareTask.get_vm_info(service_instance, vm_name)
            if not info:
                results.append(f"- ⚠️ Could not retrieve info for VM: {vm_name}")
                continue

            disks_html = '<ul>' + ''.join([
                f"<li>{d['name']}: {d['size_gb']} GB</li>" for d in info['disks']
            ]) + '</ul>'

            power_state_map = {
                'poweredOn': 'ON',
                'poweredOff': 'OFF',
                'suspended': 'Suspended'
            }
            power = power_state_map.get(info['power_state'], info['power_state'])

            result = (
                f"<div style='margin-top:10px;'>"
                f"<b>{info['name']}</b><br>"
                f"Power: <i>{power}</i><br>"
                f"ESXi Host: <i>{info['host_name']}</i><br>"
                f"CPU: <i>{info['cpu_cores']} cores</i><br>"
                f"RAM: <i>{info['ram_size_gb']} GB</i><br>"
                f"IP: <i>{info['ip_address'] or 'N/A or VMware Tools is not installed.'}</i><br>"
                f"DNS: <i>{info['dns_name'] or 'N/A or VMware Tools is not installed.'}</i><br>"
                f"Disks: {disks_html}"
                f"</div><hr>"
            )
            results.append(result)
        return '\n'.join(results).strip()

    finally:
        vc_client.disconnect()


def get_vm_events_by_name(vm_name: str, host: str, user: str, password: str, days: int = 7, limit: int = 20) -> str:
    """Get VM events for a specific VM name within the specified number of days"""
    if not vm_name or len(vm_name.strip()) < 4:
        return "🔒 VM name must be at least 4 characters long."

    if days < 1 or days > 30:
        return "🔒 Days must be between 1 and 30."

    if limit < 1 or limit > 100:
        return "🔒 Limit must be between 1 and 100."

    vc_client = VCenterClient(host, user, password)
    try:
        service_instance = vc_client.get_instance()
        events = VMwareTask.get_vm_events(service_instance, vm_name.strip(), days, limit)

        if events is None:
            return f"❌ VM '<b>{vm_name}</b>' not found."

        if not events:
            return f"📋 No events found for VM '<b>{vm_name}</b>' in the last {days} day(s)."

        # Format events for HTML display
        events_html = []
        events_html.append(f"<div style='margin-top:10px;'>")
        events_html.append(f"<b>📋 Events for VM: {vm_name}</b> (Last {days} day(s), Max {limit} events)<br><br>")
        
        for i, event in enumerate(events, 1):
            event_class = "event-info"
            if "error" in event['event_type'].lower() or "fault" in event['event_type'].lower():
                event_class = "event-error"
            elif "power" in event['event_type'].lower():
                event_class = "event-power"
            
            events_html.append(f"<div style='margin-bottom:8px; padding:5px; border-left:3px solid #ccc;'>")
            events_html.append(f"<small><b>{i}.</b> {event['timestamp']}</small><br>")
            events_html.append(f"<b>Type:</b> <i>{event['event_type']}</i><br>")
            events_html.append(f"<b>Message:</b> {event['message']}")
            if event['user']:
                events_html.append(f"<br><b>User:</b> <i>{event['user'].strip('() ')}</i>")
            events_html.append(f"</div>")
        
        events_html.append(f"</div>")
        
        return ''.join(events_html)

    except Exception as e:
        return f"❌ Error retrieving events for VM '<b>{vm_name}</b>': {str(e)}"
    
    finally:
        vc_client.disconnect()
