import boto3

# Initialize the IoT client
iot_client = boto3.client('iot')

# Retrieve a list of devices (Things)
def get_device_list():
    response = iot_client.list_things()
    return response['things']

# Enable anomaly detection on a specific device
def enable_anomaly_detection(device_id):
    response = iot_client.update_thing(
        thingName=device_id,
        thingTypeName='AnomalyDetectionEnabled',
        thingGroups=['AnomalyDetection']
    )
    return response

# Monitor and respond to alerts using AWS IoT Events
def monitor_alerts():
    alerts_client = boto3.client('iot-events')
    alerts = alerts_client.list_alerts()
    for alert in alerts['alertSummaries']:
        if alert['severity'] == 'CRITICAL':
            print(f"Critical Alert for device {alert['deviceId']}")
            # Trigger mitigation (e.g., isolating device, sending alert)
            # You can automate response actions such as blocking or isolating devices
