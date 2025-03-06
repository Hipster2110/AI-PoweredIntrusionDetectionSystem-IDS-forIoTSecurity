from azure.iot.hub import IoTHubRegistryManager

# Initialize the Azure IoT Hub registry manager
connection_string = "your-iothub-connection-string"
registry_manager = IoTHubRegistryManager(connection_string)

# Retrieve device information
def get_device_list():
    devices = registry_manager.get_devices()
    return devices

# Enable security monitoring for a specific device
def enable_security_monitoring(device_id):
    registry_manager.update_device_tags(device_id, {"security_monitoring": "enabled"})

# Example: Monitor alerts using Azure Security Center
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenterClient

def monitor_alerts():
    # Authenticate using Azure Default Credentials
    credential = DefaultAzureCredential()
    security_client = SecurityCenterClient(credential, "your-subscription-id")
    
    # List all security alerts
    alerts = security_client.alerts.list()
    for alert in alerts:
        if alert.severity == "High":
            print(f"High severity alert for device {alert.device_id}")
            # Trigger mitigation (e.g., blocking the device, sending alerts)
            # You can automate response actions, like blocking or isolating devices based on the alert severity
