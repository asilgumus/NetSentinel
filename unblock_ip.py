import os

suspicious_ip = input("Which ip do you want to unblock")

suspicious_ip = str(suspicious_ip)

os.system(f'netsh advfirewall firewall delete rule name="Block {suspicious_ip}"')
print("Successful")