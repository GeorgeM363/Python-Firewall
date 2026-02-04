import os
import requests
def send_simple_message(blocked_ip):
    return requests.post(
        "https://api.mailgun.net/v3/sandbox0ec32a20785640f7b1aa304969d83570.mailgun.org/messages",
        auth=("api", os.getenv('API_KEY', 'API_KEY')),
        data={
            "from": "Mailgun Sandbox <postmaster@sandbox0ec32a20785640f7b1aa304969d83570.mailgun.org>",
            "to": "User <glollol205@gmail.com>",
            "subject": "Potential Attack Blocked",
            "text": f"Attention, we detected a suspicious connection and dropped it\n\nBlocked IP: {blocked_ip}"
        }
    )

def send_message_requests():
    return requests.post(
        "https://api.mailgun.net/v5/sandbox/auth_recipients?email=your-email@example.com",
        auth=("api", "API_KEY"))

def main():
    response = send_simple_message()
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()