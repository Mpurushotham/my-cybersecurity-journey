I have found comprehensive Python examples for security automation using Microsoft security tools and Azure Cloud. These examples cover everything from authentication to real-world automation scenarios with Microsoft Defender for Cloud, Defender for Endpoint, and security orchestration.

### 🔐 Authentication and Core Concepts

Before diving into automation scripts, it's crucial to understand the recommended authentication method. Microsoft advises using **passwordless connections** for real-world applications to enhance security by eliminating the need to manage sensitive credentials in your code.

The `DefaultAzureCredential` class from the `azure-identity` library is the ideal choice. It seamlessly supports both local development and production environments by automatically chaining through multiple credential types.

First, install the necessary packages:
```bash
pip install azure-identity azure-eventhub azure-security
```

Here is how you can use `DefaultAzureCredential`:

```python
from azure.identity import DefaultAzureCredential
from azure.security.defender import DefenderClient

# Authenticate using DefaultAzureCredential, which supports multiple authentication methods
credential = DefaultAzureCredential()
client = DefenderClient(credential=credential)
```

### 📡 Interacting with Microsoft Security APIs

Here are practical examples for working with key Microsoft security services.

#### 1. Exporting Hosts from Microsoft Defender for Endpoint

This script fetches a list of all machines monitored by Defender for Endpoint, handling API pagination to ensure you get all records.

```python
import requests
import json

tenant_id = "<your_tenant_id>"
app_id = "<your_app_id>"
app_secret = "<your_client_secret>"

def get_token():
    body = {
        "resource": "https://api.securitycenter.windows.com",
        "client_id": app_id,
        "client_secret": app_secret,
        "grant_type": "client_credentials"
    }
    response = requests.post(f"https://login.windows.net/{tenant_id}/oauth2/token", data=body)
    return response.json()["access_token"]

def list_all_machines(auth_token):
    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    skip = 0
    top = 1000  # Page size
    all_machines = []

    while True:
        # API call with pagination parameters
        url = f"https://api.securitycenter.windows.com/api/machines?$skip={skip}&$top={top}"
        response = requests.get(url, headers=headers)
        data = response.json()

        if 'value' not in data or not data['value']:
            break  # Exit loop if no more results

        all_machines.extend(data['value'])
        skip += top

    return all_machines

# Get the data
token = get_token()
machines = list_all_machines(token)

# Example: Print computer names and their risk scores
for machine in machines:
    print(f"Computer: {machine.get('computerDnsName', 'N/A')}, Risk Score: {machine.get('riskScore', 'N/A')}")

# Save to a JSON file for further analysis
with open('defender_hosts.json', 'w') as f:
    json.dump(machines, f, indent=4)
```

#### 2. Sending Security Events to Azure Event Hubs

Azure Event Hubs is a common endpoint for streaming security log data. This example shows how to send events passwordlessly.

```python
import asyncio
from azure.eventhub import EventData
from azure.eventhub.aio import EventHubProducerClient
from azure.identity.aio import DefaultAzureCredential

EVENT_HUB_FULLY_QUALIFIED_NAMESPACE = "<your_namespace>.servicebus.windows.net"
EVENT_HUB_NAME = "<your_eventhub_name>"

async def send_security_events():
    credential = DefaultAzureCredential()
    producer = EventHubProducerClient(
        fully_qualified_namespace=EVENT_HUB_FULLY_QUALIFIED_NAMESPACE,
        eventhub_name=EVENT_HUB_NAME,
        credential=credential,
    )
    print("Producer client created successfully.")
    async with producer:
        event_data_batch = await producer.create_batch()
        # Add simulated security events to the batch
        event_data_batch.add(EventData('{"AlertType": "SuspiciousPowerShell", "Severity": "High"}'))
        event_data_batch.add(EventData('{"AlertType": "MalwareDetected", "Severity": "Critical"}'))
        await producer.send_batch(event_data_batch)
        print("Security events sent successfully.")
    await credential.close()

# Run the async function
asyncio.run(send_security_events())
```

### ⚙️ Real-World Automation Scenarios

Here are practical automation workflows you can build by combining the above concepts.

#### 1. Automated Vulnerability Reporting

This script correlates data from the Defender for Endpoint API and the Microsoft Graph API to generate personalized vulnerability reports for end-users.

```python
# ... (get_token function from previous examples)

def get_defender_machines(token):
    """Gets machines with vulnerabilities from Defender for Endpoint."""
    headers = {'Authorization': f'Bearer {token}'}
    url = "https://api.securitycenter.microsoft.com/api/machines"
    response = requests.get(url, headers=headers)
    return response.json().get('value', [])

def get_machine_recommendations(token, machine_id):
    """Gets specific security recommendations for a machine."""
    headers = {'Authorization': f'Bearer {token}'}
    url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/recommendations"
    response = requests.get(url, headers=headers)
    return response.json().get('value', [])

def get_intune_device_details(graph_token, azure_ad_device_id):
    """Gets device owner details from Microsoft Graph (Intune)."""
    headers = {'Authorization': f'Bearer {graph_token}'}
    url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=azureADDeviceId eq '{azure_ad_device_id}'"
    response = requests.get(url, headers=headers)
    devices = response.json().get('value', [])
    return devices[0] if devices else None

# Main workflow
defender_token = get_token() # Token for Defender API
graph_token = get_token() # Token for Microsoft Graph API (resource = 'https://graph.microsoft.com')

vulnerable_machines = get_defender_machines(defender_token)

user_report = {}

for machine in vulnerable_machines:
    recommendations = get_machine_recommendations(defender_token, machine['id'])
    if recommendations:
        device_details = get_intune_device_details(graph_token, machine['aadDeviceId'])
        if device_details:
            user_upn = device_details.get('userPrincipalName')
            if user_upn not in user_report:
                user_report[user_upn] = []
            user_report[user_upn].append({
                'deviceName': machine['computerDnsName'],
                'recommendations': [rec['recommendationName'] for rec in recommendations]
            })

# user_report now contains a structure suitable for generating and sending personalized emails.
print("Generated user report:", user_report)
```

#### 2. Triggering Automated Remediation with Logic Apps

Microsoft Defender for Cloud's **Workflow Automation** feature can trigger an Azure Logic App when a security alert or recommendation is generated. You can pass the alert details (like severity or resource ID) to the Logic App, which can then run remediation tasks such as:
- **Isolating a VM** in response to a high-severity alert.
- **Creating a ticket** in your IT service management (ITSM) system.
- **Sending a detailed notification** to a Slack or Teams channel.

### 🔧 Operational Tips and Best Practices

- **Handle API Limitations**: As noted in a community question, some Azure APIs have result limits (e.g., 1000 records). Always implement **pagination**, as shown in the host export example, to retrieve complete datasets.
- **Secure Your Credentials**: For production, avoid hard-coding secrets. Use **Azure Key Vault** or **managed identities** for Azure services to securely access your credentials.
- **Leverage Official Resources**: The **Microsoft Defender for Cloud GitHub repository** is a valuable source for community-driven scripts, Logic App templates, and programmatic remediation tools.

These examples should give you a solid foundation for building your own security automations. 
