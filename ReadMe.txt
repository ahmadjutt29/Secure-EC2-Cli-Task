# 🔐 EC2 Secure CLI with S3 Logging

This project provides a **secure CLI application** (`connect.py`) that:
- Authenticates users with **bcrypt password hashing**
- Executes **AWS CLI commands** for whitelisted services
- Logs **all activity** (commands, responses, sessions) into **Amazon S3**
- Supports **interactive SSH** into an EC2 instance (auto-discovered or manually configured)

---

## 📋 Prerequisites

### 1. AWS Account & IAM Setup
You need an AWS account with permissions to manage:
- **EC2** (`DescribeInstances`, `StartInstances`, etc.)
- **S3** (`ListBucket`, `PutObject`)

Create a role for your EC2 instance (e.g., `EC2CLIAppRole`) and attach a policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:ListBucket",
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "arn:aws:s3:::mycompany-ec2-logs-20250826",
        "arn:aws:s3:::mycompany-ec2-logs-20250826/*"
      ]
    }
  ]
}
2. Install Required Tools
AWS CLI v2

bash
Copy
Edit
aws --version
Python 3.10+
Install virtual environment:

bash
Copy
Edit
python3 -m venv venv
source venv/bin/activate
Python dependencies

bash
Copy
Edit
pip install boto3 botocore bcrypt
3. Configure AWS CLI
Run:

bash
Copy
Edit
aws configure
Provide:

AWS Access Key ID

AWS Secret Access Key

Default region name: eu-north-1

Output format: json

4. Prepare EC2 Instance
Launch an Amazon Linux EC2 instance in eu-north-1.

Add tags:

do-not-nuke = true

team = abc

Create a Key Pair (e.g., MyKeyPair.pem) and download it.

Add Inbound SSH rule (port 22) in Security Group.

5. Create S3 Bucket
Create an S3 bucket for logs:

bash
Copy
Edit
aws s3 mb s3://mycompany-ec2-logs-20250826 --region eu-north-1
⚙️ Configuration
Edit connect.py and update values:

python
Copy
Edit
ADMIN_PASSWORD_HASH = "<bcrypt_hash_here>"  # Use bcrypt hash, not plain text
S3_BUCKET = "mycompany-ec2-logs-20250826"
AWS_REGION = "eu-north-1"
SESSION_TIMEOUT = 3600
MAX_CMD_TIMEOUT = 300

# EC2 SSH details
EC2_PUBLIC_IP = ""     # Leave blank to auto-discover by tags
EC2_USER = "ec2-user"  # Default for Amazon Linux
SSH_KEY_PATH = "/path/to/MyKeyPair.pem"
👉 To generate a bcrypt password hash:

bash
Copy
Edit
python3
>>> import bcrypt
>>> bcrypt.hashpw("MySecurePassword".encode(), bcrypt.gensalt())
Copy the output hash into ADMIN_PASSWORD_HASH.

▶️ Running the Program
Activate environment:

bash
Copy
Edit
source venv/bin/activate
Run the CLI:

bash
Copy
Edit
python connect.py
Authenticate:

makefile
Copy
Edit
Username: admin
Password: ****
Execute AWS commands:

bash
Copy
Edit
ec2-aws> aws ec2 describe-instances
ec2-aws> aws s3 ls
SSH into EC2:

bash
Copy
Edit
ec2-aws> ssh
Connecting to ec2-user@<EC2_Public_IP> ...
Exit session:

bash
Copy
Edit
ec2-aws> exit
📝 Logging
Logs are automatically uploaded to S3:

Consolidated Logs (daily):

bash
Copy
Edit
s3://mycompany-ec2-logs-20250826/consolidated/consolidated-logs-YYYY-MM-DD.log
Per-user Session Logs:

bash
Copy
Edit
s3://mycompany-ec2-logs-20250826/users/<username>/session-logs-YYYY-MM-DD-HH-MM-SS.log
Example log entry:

json
Copy
Edit
{
  "username": "admin",
  "aws_command": "aws ec2 describe-instances",
  "response": "...",
  "timestamp": "2025-08-26T14:36:09Z",
  "session_id": "abc123",
  "return_code": 0
}
⚠️ Security Notes
Passwords stored only as bcrypt hashes

Logs cannot be modified once stored in S3

IAM policies follow least privilege principle

SSH access requires .pem private key

📦 Tech Stack
Python 3

boto3 – AWS SDK for Python

bcrypt – Password hashing

AWS CLI v2 – For executing real AWS commands

Amazon EC2 + S3 – Infrastructure

🚀 Future Improvements
Multi-user authentication with IAM

CloudWatch monitoring of CLI activity

MFA (Multi-Factor Authentication)

Session timeout enforcement

🖥️ GitHub Repo Setup
Initialize repo:

bash
Copy
Edit
git init
git branch -M main
Add remote:

bash
Copy
Edit
git remote add origin https://github.com/<your-username>/<your-repo>.git
Add files & commit:

bash
Copy
Edit
git add .
git commit -m "Initial commit: Secure EC2 CLI with S3 Logging"
Push to GitHub:

bash
Copy
Edit
git push -u origin main
✅ Example Run
bash
Copy
Edit
$ python connect.py
CLI EC2 Application — connect.py
Username: admin
Password:
Authenticated. Session id: 3ab4c9d...
admin@ec2-aws> aws s3 ls
2025-08-26 14:36:09 mycompany-ec2-logs-20250826
admin@ec2-aws> ssh
Connecting to ec2-user@51.21.200.155 ...
[connected to EC2 instance]