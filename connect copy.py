import boto3, botocore, bcrypt, getpass, uuid, shlex, subprocess, json, time
from datetime import datetime, timezone
import sys, signal, os

# ============ CONFIGURATION ============
ADMIN_PASSWORD_HASH = "$2b$12$ROjIxXP4Y6IzirfATMftfuzasLln56SEKAF0P3ZR6Vh7i2RwceRPq"
S3_BUCKET = "mycompany-ec2-logs-20250826"
AWS_REGION = "eu-north-1"
SESSION_TIMEOUT = 3600
MAX_CMD_TIMEOUT = 300
WHITELIST_SERVICES = {
    "ec2","s3","s3api","iam","sts","lambda","cloudformation","logs",
    "cloudwatch","rds","sns","sqs","kms","secretsmanager","autoscaling","organizations"
}

EC2_PUBLIC_IP = ""
EC2_USER = "ec2-user"
SSH_KEY_PATH = "/Users/mac/Downloads/MyKeyPair.pem"
# ====================================

s3 = boto3.client("s3", region_name=AWS_REGION)
ec2 = boto3.client("ec2", region_name=AWS_REGION)

def is_bcrypt_hash(s):
    return isinstance(s, str) and s.startswith("$2")

def check_password(entered):
    if is_bcrypt_hash(ADMIN_PASSWORD_HASH):
        try:
            return bcrypt.checkpw(entered.encode(), ADMIN_PASSWORD_HASH.encode())
        except Exception:
            return False
    else:
        return entered == ADMIN_PASSWORD_HASH

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def first_non_option_token(tokens):
    for t in tokens:
        if t == "aws": continue
        if t.startswith("-"): continue
        return t
    return None

def append_to_s3(bucket, key, data_bytes):
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        existing = obj["Body"].read()
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NoSuchObject"):
            existing = b""
        else:
            raise
    combined = existing + data_bytes
    s3.put_object(Bucket=bucket, Key=key, Body=combined)

def upload_log_entries(username, session_id, entries):
    if not entries:
        return
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cons_key = f"consolidated/consolidated-logs-{day}.log"
    session_ts = session_id_ts(session_id)
    user_key = f"users/{username}/session-logs-{session_ts}.log"
    lines = [json.dumps(e, ensure_ascii=False) for e in entries]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    append_to_s3(S3_BUCKET, cons_key, payload)
    append_to_s3(S3_BUCKET, user_key, payload)

def session_id_ts(session_id):
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")

def stream_subprocess(cmd_list, timeout):
    try:
        p = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return 127, "aws CLI not found on PATH. Install AWS CLI v2 on the instance.\n"
    out_lines, start = [], time.time()
    try:
        while True:
            line = p.stdout.readline()
            if line:
                print(line, end="", flush=True)
                out_lines.append(line)
            else:
                if p.poll() is not None:
                    break
                if time.time() - start > timeout:
                    try:
                        p.kill()
                    except Exception:
                        pass
                    out_lines.append("[COMMAND TIMED OUT]\n")
                    break
                time.sleep(0.05)
    except Exception as e:
        try:
            p.kill()
        except Exception:
            pass
        out_lines.append(f"[ERROR STREAMING OUTPUT] {str(e)}\n")
    return (p.returncode if p.returncode is not None else -1, "".join(out_lines))

def graceful_exit(signum, frame):
    print("\nExiting (signal received).")
    raise KeyboardInterrupt

def get_ec2_public_ip():
    try:
        resp = ec2.describe_instances(
            Filters=[
                {"Name": "tag:do-not-nuke", "Values": ["true"]},
                {"Name": "tag:team", "Values": ["abc"]},
                {"Name": "instance-state-name", "Values": ["running"]}
            ]
        )
    except botocore.exceptions.ClientError as e:
        print(f"[EC2 LOOKUP ERROR] {e}")
        return None

    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            ip = inst.get("PublicIpAddress")
            if ip:
                return ip
    return None

def main():
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    print("CLI EC2 Application — connect.py")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    if not check_password(password):
        print("Authentication failed.")
        sys.exit(1)

    session_id = uuid.uuid4().hex
    expires_at = time.time() + SESSION_TIMEOUT
    session_log_entries = []
    print(f"Authenticated. Session id: {session_id}. Timeout in {SESSION_TIMEOUT} seconds.")

    try:
        while True:
            if time.time() > expires_at:
                print("Session timed out.")
                break

            try:
                cmd = input(f"{username}@ec2-aws> ").strip()
            except EOFError:
                break

            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                print("Exiting by user request.")
                break

            if cmd.lower() == "ssh":
                target_ip = EC2_PUBLIC_IP.strip() if EC2_PUBLIC_IP else None
                if not target_ip:
                    target_ip = get_ec2_public_ip()
                if not target_ip:
                    print("No running EC2 instance found with tags (do-not-nuke=true, team=abc).")
                    continue

                print(f"Connecting to {EC2_USER}@{target_ip} ...")
                ssh_cmd = ["ssh", "-i", SSH_KEY_PATH, f"{EC2_USER}@{target_ip}"]
                try:
                    entry_start = {
                        "username": username,
                        "action": "ssh_start",
                        "details": f"Connecting to {EC2_USER}@{target_ip}",
                        "timestamp": now_iso(),
                        "session_id": session_id
                    }
                    upload_log_entries(username, session_id, [entry_start])
                except Exception as e:
                    print(f"[LOGGING ERROR] Failed to upload SSH start event: {e}")

                try:
                    subprocess.call(ssh_cmd)
                except Exception as e:
                    print(f"[SSH ERROR] {e}")

                try:
                    entry_end = {
                        "username": username,
                        "action": "ssh_end",
                        "details": f"Disconnected from {EC2_USER}@{target_ip}",
                        "timestamp": now_iso(),
                        "session_id": session_id
                    }
                    upload_log_entries(username, session_id, [entry_end])
                except Exception as e:
                    print(f"[LOGGING ERROR] Failed to upload SSH end event: {e}")
                continue

            tokens = shlex.split(cmd)
            if tokens[0] != "aws":
                tokens = ["aws"] + tokens
            service = first_non_option_token(tokens[1:]) or first_non_option_token(tokens)
            if service is None or service not in WHITELIST_SERVICES:
                print(f"Command denied. Service '{service}' not in whitelist.")
                continue

            rc, output = stream_subprocess(tokens, MAX_CMD_TIMEOUT)
            entry = {
                "username": username,
                "aws_command": " ".join(tokens),
                "response": output,
                "timestamp": now_iso(),
                "session_id": session_id,
                "return_code": rc
            }
            session_log_entries.append(entry)
            try:
                upload_log_entries(username, session_id, [entry])
            except Exception as e:
                print(f"[LOGGING ERROR] Failed to upload logs to S3: {e}")

    except KeyboardInterrupt:
        pass
    finally:
        print("Goodbye.")

if __name__ == "__main__":
    main()
